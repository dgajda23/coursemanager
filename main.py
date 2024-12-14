from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# Error messages and codes
ERROR_400 = ({"Error": "The request body is invalid"}, 400)
ERROR_401 = ({"Error": "Unauthorized"}, 401)
ERROR_403 = ({"Error": "You don't have permission on this resource"}, 403)
ERROR_404 = ({"Error": "Not found"}, 404)
ERROR_409 = ({"Error": "Enrollment data is invalid"}, 409)

# Globals
USERS = "users"
COURSES = "courses"
STUDENTS = "students"
AVATAR = "avatar"
ADMIN = "admin"
INSTRUCTOR = "instructor"
STUDENT = "student"

# OAuth Credentials
CLIENT_ID = 'qEWK7xq4c8F6gMz87OXp6jCS4uEBTSoc'
CLIENT_SECRET = 'QlG8nW2MFRwminjjBoPi9d0T3rSS8cQm_jwtBQqZiL5Ng5zwPerYwPUV7ww9SfoV'
DOMAIN = 'dev-szec6yfm156i6z2g.us.auth0.com'

# Bucket
AVATAR_BUCKET = "avatar_bucket_gajdad"

# AuthError Class
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

# OAuth Registration
ALGORITHMS = ["RS256"]
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# Generate a JWT for a registered user of the app
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()

    # Request body is valid
    if not 'username' in content or not 'password' in content:
        return (ERROR_400)

    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    # Username/Password invalid
    if r.status_code == 403:
        return(ERROR_401)

    token = r.json().get("id_token")
    if token:
        return ({"token": token}, 200)

# Return an array with all 9 pre-created users from the kind “users” in Datastore
# The user accessing must be an admin
@app.route('/' + USERS, methods=['GET'])
def get_users():
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    user_role = get_user_role(payload.get('sub'))
    # User isn't in Datastore
    if not user_role:
        return ERROR_403
    
    # User isn't an admin
    if user_role != ADMIN:
        return ERROR_403
    
    query = client.query(kind=USERS)
    users = list(query.fetch())

    response = []
    for user in users:
        user_data = {
            "id": user.key.id,
            "role": user.get('role'),
            "sub": user.get('sub')
        }
        response.append(user_data)

    return(response, 200)


# Return the details of a user
@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    user_role = get_user_role(payload.get('sub'))
    user = get_user_jwt(user_id, payload.get('sub'))
    # User's sub isnt't in datastore or user sub doesnt match user id
    if not user or not user_role:
        return ERROR_403
    
    user_to_return = {
        "id": user.key.id,
        "role": user_role,
        "sub": payload.get('sub')
    }

    # If user has avatar add it to the return user
    if 'avatar_url' in user:
        user_to_return['avatar_url'] = user.get('avatar_url')
    
    # Add courses property if a student or instructor
    if user_role == STUDENT or user_role == INSTRUCTOR:
        if not user.get('courses'):
            user_to_return['courses'] = []
        else:
            user_to_return['courses'] = user.get('courses')
    
    return (user_to_return, 200)

# Upload the .png in the request as the avatar of the user’s avatar. If there is already an avatar for the
# user, it gets updated with the new file. The file must be uploaded to Google Cloud Storage.
@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['POST'])
def create_or_update_avatar(user_id):

    if 'file' not in request.files:
        return(ERROR_400)
    
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return(ERROR_401)
    
    file_obj = request.files['file']
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    avatar_url = f"{request.host_url}users/{user_id}/avatar"

    user = get_user_jwt(user_id, payload.get('sub'))
    # User isn't in Datastore
    if not user:
        return(ERROR_403)
    
    user['avatar_url'] = avatar_url
    user['file_name'] = file_obj.filename

    client.put(user)

    return ({"avatar_url": avatar_url}, 200)

# @app.route('/images', methods=['POST'])
# def store_image():
#     # Any files in the request will be available in request.files object
#     # Check if there is an entry in request.files with the key 'file'
#     if 'file' not in request.files:
#         return ('No file sent in request', 400)
#     # Set file_obj to the file sent in the request
#     file_obj = request.files['file']
#     # If the multipart form data has a part with name 'tag', set the
#     # value of the variable 'tag' to the value of 'tag' in the request.
#     # Note we are not doing anything with the variable 'tag' in this
#     # example, however this illustrates how we can extract data from the
#     # multipart form data in addition to the files.
#     if 'tag' in request.form:
#         tag = request.form['tag']
#     # Create a storage client
#     storage_client = storage.Client()
#     # Get a handle on the bucket
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob object for the bucket with the name of the file
#     blob = bucket.blob(file_obj.filename)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Upload the file into Cloud Storage
#     blob.upload_from_file(file_obj)
#     return ({'file_name': file_obj.filename},201)

# @app.route('/images/<file_name>', methods=['GET'])
# def get_image(file_name):
#     storage_client = storage.Client()
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     # Create a blob with the given file name
#     blob = bucket.blob(file_name)
#     # Create a file object in memory using Python io package
#     file_obj = io.BytesIO()
#     # Download the file from Cloud Storage to the file_obj variable
#     blob.download_to_file(file_obj)
#     # Position the file_obj to its beginning
#     file_obj.seek(0)
#     # Send the object as a file in the response with the correct MIME type and file name
#     return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

# @app.route('/images/<file_name>', methods=['DELETE'])
# def delete_image(file_name):
#     storage_client = storage.Client()
#     bucket = storage_client.get_bucket(PHOTO_BUCKET)
#     blob = bucket.blob(file_name)
#     # Delete the file from Cloud Storage
#     blob.delete()
#     return '',204

# Return the file stored in Google Cloud Storage as the user’s avatar
@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['GET'])
def get_avatar(user_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    user = get_user_jwt(user_id, payload.get('sub'))
    # User isn't in Datastore
    if not user:
        return(ERROR_403)
    
    if 'avatar_url' not in user:
        return(ERROR_404)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(user.get('file_name'))    
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    return(send_file(file_obj, mimetype='image/x-png', download_name=user.get('file_name')), 200)

# Delete the file stored in Google Cloud Storage as the user’s avatar.
@app.route('/' + USERS + '/<int:user_id>/' + AVATAR, methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    user = get_user_jwt(user_id, payload.get('sub'))
    # User isn't in Datastore
    if not user:
        return(ERROR_403)
    
    if 'avatar_url' not in user:
        return(ERROR_404)
    
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_BUCKET)
    blob = bucket.blob(user.get('file_name'))
    blob.delete()

    # Updating the user in DataStore
    del user['file_name']
    del user['avatar_url']

    client.put(user)

    return ('', 204)

# Create a course
@app.route('/' + COURSES, methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    if not get_user_role(payload.get('sub')) == ADMIN:
        return ERROR_403

    content = request.get_json()
    if not course_req_is_valid(content):
        return(ERROR_400)
    
    instructor = client.get(key=client.key(USERS, content['instructor_id'])) 
    if instructor is None or get_user_role(instructor.get('sub')) != INSTRUCTOR:
        return(ERROR_400)
    
    if not get_user_jwt(content['instructor_id'], instructor.get('sub')):
        return(ERROR_400)
    
    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update({
        'instructor_id': content['instructor_id'],
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
    })
    client.put(new_course)
    new_course['id'] = new_course.key.id
    course_url = f"{request.host_url}courses/{new_course.key.id}"
    new_course['self'] = course_url

    if not instructor.get('courses'):
        instructor['courses'] = [course_url]
    else:
        instructor['courses'].append(course_url)

    client.put(instructor)

    return (new_course, 201)

# Paginated list of courses
@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))

    query = client.query(kind=COURSES)
    query.order = ['subject']
    
    courses = list(query.fetch(limit=limit, offset=offset))

    course_entries = []
    for course in courses:
        course['id'] = course.key.id
        course['self'] = f"{request.host_url}courses/{course.key.id}"
        course_entries.append(course)

    total_count = len(list(query.fetch()))

    next_url = None
    if offset + limit < total_count:
        next_url = f"{request.host_url}courses?limit={limit}&offset={offset + limit}"
    
    response = {'courses': course_entries}

    if next_url:
        response['next'] = next_url

    return (response, 200)

# Get a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course = client.get(key=client.key(COURSES, course_id))
    if course is None:
        return (ERROR_404)
    
    course['self'] = f"{request.host_url}courses/{course.key.id}"
    course['id'] = course.key.id

    return (course, 200)

# Update a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    course = client.get(key=client.key(COURSES, course_id))
    if not course or get_user_role(payload.get('sub')) not in [ADMIN, INSTRUCTOR]:
        return(ERROR_403)
    
    content = request.get_json()
    # Check if the instructor id given is valid
    if 'instructor_id' in content:
        newInstructor = client.get(key=client.key(USERS, content['instructor_id'])) 
        if newInstructor is None or get_user_role(newInstructor.get('sub')) != INSTRUCTOR:
            return(ERROR_400)
        
        # Remove course from old instructor
        oldInstructor = client.get(key=client.key(USERS, course['instructor_id']))
        oldCourses = oldInstructor['courses']
        for courseString in oldCourses:
            if int(courseString.split('/')[-1]) == course_id:
                oldCourses.remove(courseString)
        
        oldInstructor['courses'] = oldCourses
        client.put(oldInstructor)
        
        # Add course to new instructor
        newInstructor['courses'].append(f"{request.host_url}courses/{course.key.id}")
        client.put(newInstructor)
        
    for key in content:
        course[key] = content[key]

    client.put(course)
    course['id'] = course.key.id
    course['self'] = f"{request.host_url}courses/{course.key.id}"

    return (course, 200)

# Delete a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    courseToRemove = client.get(key=client.key(COURSES, course_id))
    if not courseToRemove or get_user_role(payload.get('sub')) != ADMIN:
        return(ERROR_403)
    
    # Iterate through all the users, if they are an instructor or students, remove the course within them
    query = client.query(kind=USERS)
    users = list(query.fetch())

    for user in users:
        if get_user_role(user.get('sub')) == ADMIN:
            continue

        if 'courses' in user:
            updated_courses = [course for course in user['courses'] if int(course.split('/')[-1]) != course_id]

            if len(updated_courses) != len(user['courses']):
                user['courses'] = updated_courses
                client.put(user)
        
    client.delete(courseToRemove.key)
    return('', 204)

# Update the enrollment of a student
@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['PATCH'])
def update_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    courseToUpdate = client.get(key=client.key(COURSES, course_id))
    user_role = get_user_role(payload.get('sub'))
    if not courseToUpdate or user_role not in [ADMIN, INSTRUCTOR]:
        return(ERROR_403)
    
    if user_role == INSTRUCTOR:
        instructor = get_user_by_sub(payload.get('sub'))
        if not instructor or not 'courses' in instructor:
            return (ERROR_403)
        
        # Checking if a course of the course_id exists in this instructors courses
        course_id_str = str(course_id)
        if not any(course_id_str == courseString.split('/')[-1] for courseString in instructor['courses']):
            return(ERROR_403)
        
    # Check the body
    content = request.get_json()
    if not 'add' in content or not 'remove' in content:
        return (ERROR_409)
    
    # Checking for common value in add and remove
    if set(content['add']) & set(content['remove']):
        return(ERROR_409)
    
    # Checking if all values in the arrays correspond with user student
    invalid_add_ids = [student_id for student_id in content['add'] if not is_valid_student(student_id)]
    invalid_remove_ids = [student_id for student_id in content['remove'] if not is_valid_student(student_id)]
    if invalid_add_ids or invalid_remove_ids:
        return(ERROR_409)
    
    # Adding the courses
    for student_id in content['add']:
        student = client.get(key=client.key(USERS, student_id))
        if not student.get('courses'):
            student['courses'] = []
        course_id_str = str(course_id)
        if not any (course_id_str == courseString.split('/')[-1] for courseString in student['courses']):
            student['courses'].append(f"{request.host_url}courses/{course_id}")
        client.put(student)

    # Removing the courses
    for student_id in content['remove']:
        student = client.get(key=client.key(USERS, student_id))
        course_id_str = str(course_id)
        if any (course_id_str == courseString.split('/')[-1] for courseString in student['courses']):
            student['courses'].remove(f"{request.host_url}courses/{course_id}")
        client.put(student)

    return ('', 200)
    
# Get the enrollment for a course
@app.route('/' + COURSES + '/<int:course_id>/' + STUDENTS, methods=['GET'])
def get_course_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    # Invalid JWT
    except:
        return ERROR_401
    
    course = client.get(key=client.key(COURSES, course_id))
    user_role = get_user_role(payload['sub'])
    if not course or user_role not in [ADMIN, INSTRUCTOR]:
        return(ERROR_403)
    
    if user_role == INSTRUCTOR:
        instructor = get_user_by_sub(payload.get('sub'))
        if not instructor or not 'courses' in instructor:
            return (ERROR_403)
        
        # Checking if a course of the course_id exists in this instructors courses
        course_id_str = str(course_id)
        if not any(course_id_str == courseString.split('/')[-1] for courseString in instructor['courses']):
            return(ERROR_403)
    
    # Iterate through students and append studentID that are enrolled
    query = client.query(kind=USERS)
    query.add_filter('role', '=', STUDENT)

    students = list(query.fetch())
    toReturn = []
    course_id_str = str(course_id)
    for student in students:
        if not student.get('courses'):
            student['courses'] = []
        if any (course_id_str == courseString.split('/')[-1] for courseString in student['courses']):
            toReturn.append(student.key.id)

    return (toReturn, 200)


# Verify the JWT
# Returns the payload if the JWT is valid
# If it isn't returns None
def verify_jwt(request):
    if "Authorization" in request.headers:
        auth_header = request.headers["Authorization"].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":"Authorization header is missing"
                            }, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"
                            }, 401)
    
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"
                            }, 401)
    
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/",
            )
        except jwt.ExpiredSignatureError:
            AuthError({"code": "token_expired",
                            "description": "token is expired"
                            }, 401)
        
        except jwt.JWTClaimsError:
            AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"
                                }, 401)
        
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."
                                }, 401)
        
        # Return the JWT
        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"
                                }, 401)
    
# Return a user's role
def get_user_role(user_sub):
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())
    user = results[0]
    if not user:
        return None
    return user.get('role')

# Checks if the user id and user sub match and returns the user if they do
def get_user_jwt(user_id, user_sub):
    user = client.get(key=client.key(USERS, user_id))
    if user is None:
        return None
    # The user sub doesnt match the user id
    if user.get("sub") != user_sub:
        return None
    
    return user 

# Gets a user by their sub
def get_user_by_sub(user_sub):
    query = client.query(kind=USERS)
    query.add_filter('sub','=', user_sub)
    results = list(query.fetch())
    if results:
        return results[0]
    else:
        return None

# Checks if a user is valid and a student
def is_valid_student(user_id):
    user = client.get(key=client.key(USERS, user_id))
    return user and user.get('role') == STUDENT

# Checks if a request has all the required attributes for a course
def course_req_is_valid(request):
    required_attrs = {'subject', 'number', 'title', 'term', 'instructor_id'}
    if required_attrs.issubset(request.keys()):
        return True
    else:
        return False

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
