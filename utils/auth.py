from typing import Optional
import os
import time
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer


from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import psycopg2
from psycopg2.extras import RealDictCursor


#Models
class User(BaseModel):
    username: str
    role: str
    email: Optional[str] = None
    fullname: Optional[str] = None


class UserUpdateRequest(BaseModel):
    username: str  # Required field
    email: Optional[str] = None
    fullname: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None

class UserInDB:
    def __init__(self, username, hashed_password, **kwargs):
        self.username = username
        self.hashed_password = hashed_password
        for key, value in kwargs.items():
            setattr(self, key, value)


#For Bearer Token Authentication
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


#GLOBAL VARIABLES

# Password hashing + salt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#POSTGRESQL 
DB_NAME = "htx_app"
DB_USER = "htx_user"
DB_PASSWORD = "password"
DB_HOST = "localhost"  # e.g., 'localhost' or an IP address
DB_PORT = "5432"  # Default PostgreSQL port

# Configuration
# Secret key for hashing. Default val is 'super-secret-key'
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Session expires after 30 minutes of inactivity
MAX_SESSION_HOURS = 24  # Force re-login after 24 hours no matter what




# OAuth2 scheme - this will enable Bearer token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")






async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Retrieves the current authenticated user from the provided JWT token.

    This function:
    - Decodes the JWT token to extract the username.
    - Validates the token and ensures it is not expired.
    - Checks if the user exists in the database.

    If the token is invalid, expired, or the user does not exist, an HTTP 401 Unauthorized exception is raised.

    Args:
        token (str): The JWT token extracted from the Authorization header.

    Returns:
        User: The authenticated user object.

    Raises:
        HTTPException: If the token is invalid, expired, or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        # Check for absolute session timeout
        initial_login = payload.get("iat", 0)
        if time.time() - initial_login > MAX_SESSION_HOURS * 3600:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired, please login again",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def get_user(username: str):
    """
    Fetches a user from the database by their username.

    This function establishes a connection to the PostgreSQL database using the provided credentials. 
    It then executes a query to retrieve the user's details from the `users` table based on the provided `username`. 
    If the user is found, it returns an instance of `UserInDB` populated with the user's data. 
    If the user is not found or an error occurs during the database query, it returns `None`.

    Args:
        username (str): The username of the user to retrieve.

    Returns:
        UserInDB or None: Returns a `UserInDB` object if the user is found, or `None` if no user is found or an error occurs.
    """

    try:

        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Query user by username
        cur.execute("SELECT * FROM users WHERE username = %s;", (username,))
        user = cur.fetchone()

        # Close connection
        cur.close()
        conn.close()

        if user:
            return UserInDB(**user)
        return None  # User not found

    except Exception as e:
        print("Error querying database:", e)
        return None
    
# Helper functions for authentication



def verify_password(plain_password, hashed_password):
    """
    Verifies a plain text password against its hashed version.

    Args:
        plain_password (str): The password entered by the user.
        hashed_password (str): The securely stored hashed password.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)



def get_password_hash(password):
    """
    Hashes a plain text password for secure storage.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str):
    """
    Authenticates a user by verifying their credentials.

    This function:
    - Retrieves the user from the database.
    - Verifies the provided password against the stored hash.

    Args:
        username (str): The username of the user.
        password (str): The password entered by the user.

    Returns:
        User | bool: The authenticated user object if credentials are valid, False otherwise.
    """
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user



def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Generates a JSON Web Token (JWT) for authentication.

    This function:
    - Copies the provided data dictionary.
    - Adds an issued-at (`iat`) timestamp to track session creation.
    - Sets an expiration time (`exp`) based on the provided `expires_delta` or a default value.
    - Encodes the token using a secret key and the specified algorithm.

    Args:
        data (dict): The payload containing user-specific claims.
        expires_delta (Optional[timedelta]): The duration before the token expires. 
                                                If None, a default expiration is used.

    Returns:
        str: The encoded JWT token.
    """
    to_encode = data.copy()

    # Add issue time for absolute session limit tracking
    to_encode.update({"iat": time.time()})

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt