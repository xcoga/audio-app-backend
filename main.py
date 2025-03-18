
import uvicorn
import os
import boto3

from fastapi import FastAPI, Depends, HTTPException, Request,  status
from fastapi.security import  OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from datetime import  timedelta
from dotenv import load_dotenv
import psycopg2
import mimetypes
from utils.auth import User, Token,  authenticate_user, create_access_token, get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT
from routers import users
from urllib.parse import quote

#GLOBAL VARIABLES
# Load environment variables
load_dotenv()

# POSTGRESQL
conn = psycopg2.connect(
    dbname=DB_NAME,
    user=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT
)


# run using fastapi dev main.py
app = FastAPI()
app.include_router(users.router)

# For CORS
origins = [
    "http://localhost",  # Local development
    "http://localhost:3000",  # Local dev on a specific port
    "http://127.0.0.1",  # For IPv4 loopback address
    "http://frontend:3000",  # Docker Compose frontend service name
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



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

"""
Authenticates a user and generates an access token.

This function:
- Validates the provided username and password.
- If authentication fails, raises a 401 Unauthorized exception.
- If authentication succeeds, generates a JWT access token with an expiration time.
- Returns the access token in a response.

Args:
    form_data (OAuth2PasswordRequestForm): The login form containing username and password.

Returns:
    dict: A dictionary containing the access token and its type.
"""
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

"""
:ogin endpoint that provides the same functionality as the /token endpoint.

This endpoint is used to authenticate a user by accepting their username and password in the form of 
`OAuth2PasswordRequestForm`, which includes a `username` and `password`. The credentials are validated, 
and if valid, an access token is returned in the response. The returned token is used for authorization 
in further API requests.

Args:
    form_data (OAuth2PasswordRequestForm): The user credentials, including the username and password.

Returns:
    Token: A JSON Web Token (JWT) used for authenticating subsequent requests.
"""
@app.post("/login", response_model=Token)
async def login_alternative(form_data: OAuth2PasswordRequestForm = Depends()):
    """Alternative endpoint for login with the same functionality as /token"""
    return await login_for_access_token(form_data)

"""
Logs the user out of the application by removing the access token on the client-side.

In a token-based authentication system, the logout process doesn't necessarily involve server-side 
state changes. Instead, the client simply removes the stored authentication token (e.g., from localStorage 
or cookies), effectively invalidating future requests. This endpoint serves as a notification of a successful 
logout but doesn't require any server-side token invalidation.

Returns:
    dict: A message indicating the user has successfully logged out.
"""
@app.get("/logout")
async def logout():
    # For token-based auth, logout is handled client-side by removing the token
    return {"message": "Successfully logged out"}



"""
Retrieves a list of files associated with the current user from an S3 bucket, along with their metadata 
stored in a database. The endpoint returns a list of files, their descriptions, categories, and durations 
(if available) in a formatted response.

The function first queries the S3 bucket for files that belong to the current user based on their username. 
If no files are found, an empty list is returned. For each file found in the S3 response, the function then 
attempts to retrieve metadata from the database (such as audio description, category, and duration). The 
metadata, if available, is used to format the file information returned to the client.

Args:
    current_user (User): The currently authenticated user. This is automatically injected 
                            through the `Depends(get_current_user)` dependency.

Returns:
    dict: A dictionary containing the following:
        - "files": A list of formatted file objects, each containing metadata such as 
            description, category, and duration.
        - "user": The username of the currently authenticated user.
        - "total": The total number of files found for the user.
        - "error" (optional): A string error message if an exception occurs during the operation.
"""
@app.get("/list-files")
def list_files(current_user: User = Depends(get_current_user)):
    try:
        # Get files from S3
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET_NAME, Prefix=current_user.username + "/")

        if "Contents" not in response:
            print("no files found for current user: ", current_user.username)
            return {"files": [], "user": current_user.username}

        # Extract filenames from S3 response
        files = [
            obj["Key"].removeprefix(f"{current_user.username}/")
            # Copy from index 1 only. Because Amazon S3 returns the folder name at the top of the list.
            for obj in response["Contents"]
            if not obj["Key"].endswith("/")
        ]

        # Format files for client
        formatted_files = []

        for i, filename in enumerate(files):
            # Try to get metadata from database
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            try:
                cursor.execute(
                    """
                    SELECT audio_description, audio_category, audio_duration, file_path
                    FROM folder
                    WHERE username = %s AND file_name = %s
                    """,
                    (current_user.username, filename)
                )
                metadata = cursor.fetchone()
            except Exception as db_error:
                print(f"Database error for file {filename}: {str(db_error)}")
                metadata = None
            finally:
                cursor.close()

            # Create file object with expected format
            file_obj = {
                "fileName": filename,
                "file_path": '',
                "audio_description": filename.split('.')[0].replace('_', ' '),
                "audio_category": '',
                "audio_duration": '--:--',
            }

            # Add metadata if available
            if metadata:
                if metadata['audio_description']:
                    file_obj['audio_description'] = metadata['audio_description']

                if metadata['audio_duration']:
                    # Format duration as mm:ss
                    duration = metadata['audio_duration']
                    minutes = int(duration // 60)
                    seconds = int(duration % 60)
                    file_obj['audio_duration'] = f"{minutes}:{seconds:02d}"

                if metadata['audio_category']:
                    file_obj['audio_category'] = metadata['audio_category']

                if metadata['file_path']:
                    file_obj['file_path'] = metadata['file_path']

            formatted_files.append(file_obj)

        return {"files": formatted_files, "user": current_user.username, "total": len(formatted_files)}
    except Exception as e:
        print(f"Error in list_files: {str(e)}")
        return {"error": str(e)}

"""
Downloads a specified file for the currently authenticated user from an S3 bucket. 

The function retrieves the file from the S3 bucket based on the username and the provided file name, 
then returns it as a streaming response. It determines the correct MIME type based on the file extension, 
and handles UTF-8 encoding for the filename to ensure proper handling of special characters. 

If the file is not found, a 404 error is raised. Any other exceptions result in a 500 error with the error message.

Args:
    file_name (str): The name of the file to be downloaded.
    current_user (User): The currently authenticated user, automatically injected via `Depends(get_current_user)`.

Returns:
    StreamingResponse: A response containing the file's contents with appropriate headers for download.

Raises:
    HTTPException: 
        - 404: If the file is not found in the S3 bucket.
        - 500: For any other internal errors during the file retrieval process.
"""
@app.get("/download/{file_name}")
async def download_file(file_name: str, current_user: User = Depends(get_current_user)):
    file_key = f"{current_user.username}/{file_name}"
    try:
        # Get the S3 object
        response = s3_client.get_object(
            Bucket=S3_BUCKET_NAME,
            Key=file_key
        )
        
        # Determine the correct MIME type based on file extension
        content_type = mimetypes.guess_type(file_name)[0]
        if not content_type:
            # Default for audio files if the type can't be determined
            if file_name.lower().endswith(('.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a')):
                content_type = 'audio/mpeg'
            else:
                content_type = 'application/octet-stream'
        
        # Get the file size from S3 response
        content_length = response.get('ContentLength', 0)
        
        # Handle UTF-8 encoding for the filename
        # Use RFC 5987 format to properly encode UTF-8 filenames
        encoded_filename = quote(file_name.encode('utf-8'))
        
        # Create response headers with UTF-8 encoded filename
        headers = {
            'Content-Disposition': f"attachment; filename*=UTF-8''{encoded_filename}",
            'Content-Length': str(content_length),
            'Accept-Ranges': 'bytes'
        }
        
        # Return a streaming response
        return StreamingResponse(
            response['Body'],
            media_type=content_type,
            headers=headers
        )
    except s3_client.exceptions.NoSuchKey:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception as e:
        print(f"Download error: {str(e)}")  # Log the error for debugging
        raise HTTPException(status_code=500, detail=str(e))

"""
Streams music from an S3 bucket for the currently authenticated user.

This endpoint fetches the specified music file from the S3 bucket associated with the authenticated user,
determines the correct MIME type based on the file extension, and returns a streaming response with the file 
content. The response includes proper headers to support inline playback and byte-range requests.

Args:
    file_name (str): The name of the music file to be streamed.
    current_user (User): The currently authenticated user, automatically injected via `Depends(get_current_user)`.

Returns:
    StreamingResponse: A streaming response containing the music file with appropriate headers for playback.

Raises:
    HTTPException:
        - 404: If the file is not found in the S3 bucket.
        - 500: For any internal errors during the file streaming process, with an error message returned in the response.
"""
@app.get("/stream/{file_name}")
async def stream_music(file_name: str, current_user: User = Depends(get_current_user)):
    """
    Endpoint to stream music from an S3 bucket.
    """
    try:
        # Construct the full S3 key (path)
        file_key = f"{current_user.username}/{file_name}"

        # Fetch the music file from the S3 bucket
        file_obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=file_key)

        # Determine the correct MIME type based on file extension
        content_type = mimetypes.guess_type(file_name)[0]
        if not content_type:
            # Default for audio files if the type can't be determined
            if file_name.lower().endswith(('.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a')):
                content_type = 'audio/mpeg'
            else:
                content_type = 'application/octet-stream'

        # Handle UTF-8 encoding for the filename
        encoded_filename = quote(file_name.encode('utf-8'))
        
        # Create response headers with UTF-8 encoded filename
        headers = {
            'Content-Disposition': f"inline; filename*=UTF-8''{encoded_filename}",
            'Accept-Ranges': 'bytes'
        }

        # Stream the file content directly from S3 without fully loading into memory
        file_stream = file_obj['Body']

        # Return the streaming response with the appropriate MIME type and headers
        return StreamingResponse(
            file_stream, 
            media_type=content_type,
            headers=headers
        )

    except s3_client.exceptions.NoSuchKey:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

"""
Deletes a music file from the S3 bucket and its metadata from the PostgreSQL database.

This endpoint deletes the specified music file from the S3 storage associated with the authenticated user.
It also removes the corresponding metadata entry from the PostgreSQL database. If the file is successfully 
deleted from S3, but no matching metadata record is found in the database, an appropriate message is returned.
If the deletion is successful, a success message is returned. If any errors occur during the process, an error 
message is returned.

Args:
    file_name (str): The name of the music file to be deleted.
    current_user (User): The currently authenticated user, automatically injected via `Depends(get_current_user)`.

Returns:
    dict: A JSON response containing a success or error message:
        - If the file is successfully deleted from both S3 and the database, a success message is returned.
        - If the file is deleted from S3 but no metadata record is found in the database, a corresponding message is returned.
        - If there are multiple database records for the file, an error message is returned.

Raises:
    HTTPException:
        - 500: If an internal error occurs during the deletion process.
"""
@app.delete("/delete/{file_name}")
async def delete_music(file_name: str, current_user: User = Depends(get_current_user)):
    try:
        # Construct the full S3 key (path)
        file_key = f"{current_user.username}/{file_name}"

        # Delete the file from the S3 bucket
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=file_key)

        # Delete the file metadata from postgres
        # Save metadata to PostgreSQL first
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM folder
            WHERE username = %s AND file_name = %s
            """,
            (
                current_user.username,
                file_name,
            )
        )
        deleted_rows = cursor.rowcount
        conn.commit()

        if deleted_rows == 0:
            # File was deleted from S3 but no matching record in database
            return {"message": f"{file_name} was deleted from storage, but no metadata record was found"}

        elif deleted_rows == 1:
            # Return a success message
            return {"message": f"{file_name} has been deleted successfully"}
        else:
            return JSONResponse(content={"error": "should not delete multiple records. Check for bugs"}, status_code=500)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

"""
Endpoint to upload an audio file to an S3 bucket and save its metadata to a PostgreSQL database.

This endpoint allows the authenticated user to upload an audio file along with metadata (description, category, duration).
The file is first validated for correct MIME type and extension, then uploaded to an S3 bucket.
The corresponding metadata is inserted into the PostgreSQL database. If an error occurs during any part of the process, 
the operation is rolled back.

Args:
    request (Request): The incoming HTTP request containing the form data.
    current_user (User): The currently authenticated user, automatically injected via `Depends(get_current_user)`.

Returns:
    dict: A JSON response containing:
        - A success message with file details if the upload is successful.
        - An error message if the upload or metadata saving fails.

Raises:
    HTTPException:
        - 400: If required fields are missing or if an invalid audio file is uploaded.
        - 500: If an internal error occurs during the file upload or database operations.
"""
@app.post("/upload")
async def upload_audio(request: Request, current_user: User = Depends(get_current_user)):
    try:
        # Parse form data instead of JSON
        form_data = await request.form()

        # Check for required fields
        required_fields = ["file", "audio_description", "audio_category"]
        for field in required_fields:
            if field not in form_data or not form_data[field]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Missing required field: {field}"
                )

        # Get file from form data
        file = form_data["file"]
        
        # Validate that the file is an audio file
        valid_audio_extensions = ['.mp3', '.wav', '.ogg', '.m4a', '.flac', '.aac']
        valid_audio_mimetypes = [
            'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 
            'audio/m4a', 'audio/flac', 'audio/aac', 'audio/x-m4a'
        ]
        
        # Check file extension
        filename = file.filename.lower()
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in valid_audio_extensions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file type. Only audio files ({', '.join(valid_audio_extensions)}) are allowed."
            )
            
        # Check content type (MIME type)
        if file.content_type not in valid_audio_mimetypes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid content type: {file.content_type}. Only audio files are allowed."
            )
            
        print(f"Valid audio file detected: {filename}, type: {file.content_type}")

        # Get remaining fields from form data
        description = form_data["audio_description"]
        category = form_data["audio_category"]
        audio_length = form_data.get("audio_length")

        # Create user folder path
        user_folder = current_user.username
        s3_path = f"{user_folder}/{file.filename}"

        # Save metadata to PostgreSQL first
        cursor = conn.cursor()
        try:
            print("before postgres upload")
            # Insert audio metadata into database
            cursor.execute(
                """
                INSERT INTO folder 
                (username, file_name, file_path, audio_description, audio_category, audio_duration)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING file_name
                """,
                (
                    current_user.username,
                    file.filename,
                    s3_path,
                    description,
                    category,
                    audio_length
                )
            )

            # Get the ID of the inserted record
            file_id = cursor.fetchone()[0]
            conn.commit()

            print("after postgres upload")

            # Read file content
            contents = await file.read()
            print(f"Type of contents: {type(contents)}")
            print(f"Content length: {len(contents)}")

            # Upload the file to S3
            s3_client.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=s3_path,
                Body=contents,
                ContentType=file.content_type
            )

            return {
                "status": "success",
                "message": "File uploaded successfully",
                "file_id": file_id,
                "filename": file.filename
            }

        except Exception as e:
            conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}"
            )
        finally:
            cursor.close()

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )
    
"""
Endpoint to return a basic greeting and the name of the S3 bucket.
This serves as the root endpoint of the application.
Used for checking if the S3 environment variables are loaded properly.

Returns:
    dict: A JSON response containing a greeting and S3 bucket name.
"""
@app.get("/")
def read_root():
    return {"Hello": "World", "bucket_name": S3_BUCKET_NAME}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
    # To run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
