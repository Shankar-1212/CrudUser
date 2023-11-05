from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from firebase_admin import auth, firestore, credentials, initialize_app
from datetime import datetime
from fastapi.responses import RedirectResponse
import logging, traceback,os, requests
from dotenv import load_dotenv
app = FastAPI()
load_dotenv()

# Initialize Firebase Admin SDK
cred = credentials.Certificate("/home/shankar/Downloads/backend-12-7d89a-firebase-adminsdk-ij7va-b6b7482766.json")
initialize_app(cred)

db = firestore.client()
firebase_api_key = os.environ.get("FIREBASE_API_KEY")
# Pydantic models for request and response validation

class User(BaseModel):
    email: str
    password: str
    full_name: str
    username: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    email: str
    idtoken: str
    
class UserProfileRetrieve(BaseModel):
    email: str
    idtoken: str

class UserProfileUpdate(BaseModel):
    email: str
    full_name: str
    username: str
    idtoken: str
    # username: str

class UserProfileDelete(BaseModel):
    email: str
    idtoken: str

logging.basicConfig(level=logging.DEBUG)
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

@app.post("/register_user", tags=["User"])
async def register_user(user_data: User):
    """
    Register a new user.
    """
    try:
        # Print user_data to check if full_name is received correctly
        print(user_data)
        
        # Create a user in Firebase Authentication
        auth_user = auth.create_user(email=user_data.email, password=user_data.password)

        # Store user information in Firestore
        user_ref = db.collection('users').document(auth_user.uid)
        user_ref.set({
            'email': user_data.email,
            'full_name': user_data.full_name,
            'username': user_data.username,
            'created_at': datetime.now()
        })
        return {"message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login_user", tags=["User"])
async def login_user(user: UserLogin):
    
    rest_api_url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    firebase_api_key = os.getenv("FIREBASE_API_KEY")
    payload = {
        "email": user.email,
        "password": user.password,
        "returnSecureToken": True
    }

    response = requests.post(rest_api_url, params={"key": firebase_api_key}, json=payload)

    if response.status_code == 200:
        return {"idtoken": response.json().get('idToken')}
    else:
        error_message = response.json().get('error', {}).get('message', 'Authentication failed.')
        raise HTTPException(status_code=response.status_code, detail=error_message)

# Retrieve user profile endpoint
@app.post("/retrieve_user_profile", tags=["User"])
async def retrieve_user_profile(profile: UserProfileRetrieve):
    """
    Retrieve user profile information.
    """
    try:
        # Verify ID token using Firebase Auth API
        rest_api_url = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"
        firebase_api_key = os.getenv("FIREBASE_API_KEY")
        payload = {"idToken": profile.idtoken}  # Changed from retrieve_user_profile.idtoken to profile.idtoken
        response = requests.post(rest_api_url, params={"key": firebase_api_key}, json=payload)

        if response.status_code == 200:
            user_data = response.json().get('users')[0]  # Get the user data
            user_id = user_data['localId']  # Get the user's ID from Firebase Auth

            users_ref = db.collection('users')
            query = users_ref.where('email', '==', profile.email).limit(1)
            user_firestore = list(query.stream())  # Convert generator to a list for error handling

            if user_firestore:
                if user_firestore[0].id == user_id:
                    user_data = user_firestore[0].to_dict()

                    profile_data = {
                        'email': user_data.get('email'),
                        'full_name': user_data.get('full_name'),
                        'username': user_data.get('username')
                    }
                    return profile_data
                else:
                    raise HTTPException(status_code=403, detail="Unauthorized: ID token doesn't match user")
            else:
                raise HTTPException(status_code=404, detail="User profile not found")
        else:
            raise HTTPException(status_code=401, detail="Invalid ID token")
    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Internal server error") 


# Retrieve user profile endpoint

@app.put("/update_user_profile", tags=["User"])
async def update_user_profile(profile_update: UserProfileUpdate):
    """
    Update user profile information.
    """
    valid_keys = {"full_name", "username"}  # Only allow these keys to be updated

    try:
        # Verify ID token using Firebase Auth API
        rest_api_url = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"
        firebase_api_key = os.getenv("FIREBASE_API_KEY")
        payload = {"idToken": profile_update.idtoken}
        response = requests.post(rest_api_url, params={"key": firebase_api_key}, json=payload)

        if response.status_code == 200:
            user_data = response.json().get('users')[0]  # Get the user data
            user_id = user_data['localId']  # Get the user's ID from Firebase Auth

            users_ref = db.collection('users')
            query = users_ref.where('email', '==', profile_update.email).limit(1)
            user_firestore = list(query.stream())  # Convert generator to a list for error handling

            if user_firestore:
                if user_firestore[0].id == user_id:
                    user_ref = users_ref.document(user_firestore[0].id)
                    update_data = {key: value for key, value in profile_update.dict().items() if key in valid_keys}
                    user_ref.update(update_data)
                    return {"message": "User profile updated successfully"}
                else:
                    raise HTTPException(status_code=403, detail="Unauthorized: ID token doesn't match user")
            else:
                raise HTTPException(status_code=404, detail="User profile not found for the provided email")
        else:
            raise HTTPException(status_code=401, detail="Invalid ID token")
    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        logging.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Internal server error")




@app.delete("/delete_user_profile", tags=["User"])
async def delete_user_profile(profile_delete: UserProfileDelete):
    """
    Delete user profile and associated data.
    """
    try:
        # Verify ID token using Firebase Auth API
        rest_api_url = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"
        # firebase_api_key = os.getenv("FIREBASE_API_KEY")

        payload = {"idToken": profile_delete.idtoken}
        response = requests.post(rest_api_url, params={"key": firebase_api_key}, json=payload)

        if response.status_code == 200:
            user_data = response.json().get('users')[0]  # Get the user data
            user_id = user_data['localId']  # Get the user's ID from Firebase Auth

            users_ref = db.collection('users')
            query = users_ref.where('email', '==', profile_delete.email).limit(1)
            user_firestore = list(query.stream())  # Convert generator to a list for error handling

            if user_firestore:
                if user_firestore[0].id == user_id:
                    user_ref = users_ref.document(user_firestore[0].id)
                    user_ref.delete()
                    return {"message": "User account deleted successfully"}
                else:
                    raise HTTPException(status_code=403, detail="Unauthorized: ID token doesn't match user")
            else:
                raise HTTPException(status_code=404, detail="User profile not found for the provided email")
        else:
            raise HTTPException(status_code=401, detail="Invalid ID token")
    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


