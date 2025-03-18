from typing import List
from fastapi import Depends, HTTPException, Request, status,  APIRouter
import boto3
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from utils.auth import User, get_current_user, get_password_hash, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT
import asyncio

#Routed from main.py
router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

# Database connection settings
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    API call to get user details.

    Returns: User: current_user
    """
    return current_user



@router.delete("/{delete_user}")
async def delete_user(delete_user: str, current_user: User = Depends(get_current_user)):
    """
    Deletes a specified user from the system.

    Only administrators are allowed to perform this action.  
    Prevents an admin from deleting their own account or the 'admin' account.  
    If the specified user does not exist, returns a 404 error.  
    If deletion fails due to an internal error, returns a 500 error.  

    Returns: dict: A success message if the user is deleted.
    """
    # Only allow admins to delete users
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete users"
        )

    # Prevent admin from deleting their own account. (SUPERACCOUNT only. Other admins can be deleted)
    if delete_user == current_user.username or delete_user == "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account or 'admin' account."
        )

    cursor = conn.cursor()

    try:
        # Check if user exists first
        cursor.execute(
            "SELECT username FROM users WHERE username = %s", (delete_user,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{delete_user}' not found"
            )

        # Delete the user
        cursor.execute("DELETE FROM users WHERE username = %s", (delete_user,))

        # Check if any row was affected
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{delete_user}' not found"
            )

        # Commit the transaction
        conn.commit()

        #Delete all the user's uploaded audio files + metadata.
        cursor.execute("DELETE FROM folder WHERE username = %s", (delete_user,))
        # Check if any row was affected
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{delete_user}' not found"
            )

        # Commit the transaction
        conn.commit()

        s3_response = await delete_s3_folder(delete_user)

        return {
            "success": True,
            "message": f"User '{delete_user}' deleted successfully"
        }

    except Exception as e:
        # Rollback in case of error
        conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )

    finally:
        cursor.close()


async def delete_s3_folder(username):
    """
    Asynchronously delete all objects in an S3 folder for a specific user.
    
    Args:
        username (str): Username whose folder should be deleted
    
    Returns:
        dict: Result of the operation
    """
    # For AWS
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    try:
        # Create the prefix (folder path)
        prefix = f"{username}/"
        
        # For AWS SDK operations, we need to run them in a thread pool
        # since boto3 doesn't support async natively
        loop = asyncio.get_event_loop()
        
        # List all objects with the prefix
        delete_list = []
        file_count = 0
        
        # Function to run in thread pool
        def list_and_delete():
            nonlocal delete_list, file_count
            
            # List objects
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=S3_BUCKET_NAME, Prefix=prefix)
            
            # Collect all the objects to delete
            for page in pages:
                if "Contents" in page:
                    for obj in page["Contents"]:
                        delete_list.append({"Key": obj["Key"]})
                        file_count += 1
            
            # If there are no objects, return early
            if not delete_list:
                return {
                    "status": "success",
                    "message": f"No files found in folder {prefix}"
                }
            
            # Delete the objects
            s3_client.delete_objects(
                Bucket=S3_BUCKET_NAME,
                Delete={
                    'Objects': delete_list,
                    'Quiet': False
                }
            )
            
            return {
                "status": "success",
                "message": f"Successfully deleted folder {prefix}",
                "deleted_count": file_count
            }
        
        # Run the blocking operations in a thread pool
        result = await loop.run_in_executor(None, list_and_delete)
        return result
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to delete folder: {str(e)}"
        }


@router.post("/create")
async def create_user(request: Request, current_user: User = Depends(get_current_user)):
    """
    Creates a new user in the database with password hashing.

    Only administrators can create new users.  
    Ensures all required fields are provided and checks for duplicate usernames.  
    Hashes the password before storing it in the database.  
    Returns an error if the user already exists or if a database issue occurs.

    Returns:
        dict: The newly created user's details (excluding the password).
    """
    # Only allow admins to create users
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to create users"
        )

    try:
        # Get JSON data from request
        data = await request.json()

        # Check for required fields
        required_fields = ["username", "email", "fullname", "role", "password"]
        for field in required_fields:
            if field not in data or not data[field]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing required field: {field}"
                )

        cursor = conn.cursor()

        try:
            # Create users table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(255) UNIQUE NOT NULL,
                    fullname VARCHAR(255) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    hashed_password TEXT NOT NULL,
                    PRIMARY KEY (username)
                )
            """)

            # Check if user already exists
            cursor.execute(
                "SELECT username FROM users WHERE username = %s", (
                    data["username"],)
            )
            existing_user = cursor.fetchone()

            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"User '{data['username']}' already exists"
                )

            # Hash the password
            hashed_password = get_password_hash(data["password"])

            # Insert the new user using parameterized query
            cursor.execute("""
                INSERT INTO users (username, email, fullname, role, hashed_password)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data["username"],
                data["email"],
                data["fullname"],
                data["role"],
                hashed_password
            ))

            # Commit the transaction
            conn.commit()

            # Return success
            return {
                "username": data["username"],
                "email": data["email"],
                "fullname": data["fullname"],
                "role": data["role"]
            }

        except Exception as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )

        finally:
            cursor.close()
            # Close connection if you aren't using a connection pool

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating user: {str(e)}"
        )


@router.put("/update")
async def update_user(request: Request, current_user: User = Depends(get_current_user)):
    """
    Updates an existing user's details in the database.

    Only administrators can update user information.  
    Allows updating email, full name, role, and password (with proper hashing).  
    Ensures the user exists before attempting an update.  
    If no valid fields are provided, no update is performed.  
    Returns an error if the user does not exist or if a database issue occurs.

    Returns:
        dict: The updated user's details (excluding the password).
    """
    # Only allow admins to update users
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update users"
        )
     

    # Get JSON data from request
    data = await request.json()
    username = data.get("username")

    print(f"Updating user: {username} with data: {data}")  # Add logging
    
    if username == "admin" and current_user.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot update 'admin' user"
        )
    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is required"
        )

    cursor = conn.cursor()

    try:
        # Check if the user exists
        cursor.execute(
            "SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{username}' not found"
            )

        # Build a simple update query with the provided fields
        set_clauses = []
        values = []

        if "email" in data and data["email"] is not None:
            set_clauses.append("email = %s")
            values.append(data["email"])

        if "fullname" in data and data["fullname"] is not None:
            # Column name in DB is fullname
            set_clauses.append("fullname = %s")
            values.append(data["fullname"])    # Key in request is full_name

        if "role" in data and data["role"] is not None:
            set_clauses.append("role = %s")
            values.append(data["role"])

        if "password" in data and data["password"]:
            hashed_password = get_password_hash(data["password"])
            set_clauses.append("hashed_password = %s")
            values.append(hashed_password)

        if not set_clauses:
            print("No fields to update")
            return {"message": "No fields to update"}

        # Add username to the values list for the WHERE clause
        values.append(username)

        # Construct and execute the query
        query = f"""
            UPDATE users
            SET {', '.join(set_clauses)}
            WHERE username = %s
        """

        print(f"Executing query: {query} with values: {values}")  # Add logging

        cursor.execute(query, values)

        # Check how many rows were affected
        row_count = cursor.rowcount
        print(f"Rows affected: {row_count}")  # Add logging

        if row_count == 0:
            print("No rows were updated!")

        # IMPORTANT: Explicitly commit the transaction
        conn.commit()
        print("Transaction committed")

        # Fetch the updated user
        cursor.execute(
            "SELECT username, email, fullname, role FROM users WHERE username = %s", (username,))
        updated_user = cursor.fetchone()

        if not updated_user:
            print("Could not fetch updated user")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User '{username}' not found after update"
            )

        # Convert to dictionary (adjust column names as needed)
        user_dict = {
            "username": updated_user[0],
            "email": updated_user[1],
            "fullname": updated_user[2],
            "role": updated_user[3]
        }

        print(f"Returning updated user: {user_dict}")  # Add logging
        return user_dict

    except Exception as e:
        conn.rollback()
        print(f"Error updating user: {str(e)}")  # Add logging
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {str(e)}"
        )

    finally:
        cursor.close()


@router.get("/", response_model=List[User])
async def read_users(current_user: User = Depends(get_current_user)):
    """
    Retrieves a list of all users from the database.

    Only authenticated users can access this endpoint.  
    Returns a list of users with their username, full name, email, and role.  
    If no users are found, an empty list is returned.  
    Handles database errors gracefully.

    Returns:
        List[User]: A list of user objects excluding passwords.
    """
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Query all users, selecting only the needed fields
        cur.execute("SELECT username, fullname, email, role FROM users;")
        users = cur.fetchall()

        # Close connection
        cur.close()

        if users:
            return [User(**user) for user in users]
        return []  # No users found
    except Exception as e:
        print("Error querying database:", e)
        raise HTTPException(status_code=500, detail="Database error")