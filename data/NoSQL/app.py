#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, DYNAMODB_TABLE, SECERT_KEY, CONFIRM_EMAIL_SALT, SES_EMAIL_SOURCE, DYNAMODB_USER_TABLE
from flask import Flask, jsonify, abort, request, make_response, url_for, render_template, redirect, session
import time
import exifread
import json
import uuid
import boto3  
from boto3.dynamodb.conditions import Key, Attr
import pymysql.cursors
from datetime import datetime
import pytz

"""
    INSERT NEW LIBRARIES HERE (IF NEEDED)
"""

from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import ClientError
from functools import wraps
from urllib.parse import urlparse

"""
"""

app = Flask(__name__, static_url_path="")
app.config['SECRET_KEY'] = SECERT_KEY
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                            region_name=AWS_REGION)

photo_table = dynamodb.Table(DYNAMODB_TABLE)
user_table = dynamodb.Table(DYNAMODB_USER_TABLE)

UPLOAD_FOLDER = os.path.join(app.root_path,'static','media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def getExifData(path_name):
    f = open(path_name, 'rb')
    tags = exifread.process_file(f)
    ExifData={}
    for tag in tags.keys():
        if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
            key="%s"%(tag)
            val="%s"%(tags[tag])
            ExifData[key]=val
    return ExifData

def s3uploading(filename, filenameWithPath, uploadType="photos"):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
                       
    bucket = PHOTOGALLERY_S3_BUCKET_NAME
    path_filename = uploadType + "/" + filename

    s3.upload_file(filenameWithPath, bucket, path_filename)  
    s3.put_object_acl(ACL='public-read', Bucket=bucket, Key=path_filename)
    return f'''http://{PHOTOGALLERY_S3_BUCKET_NAME}.s3.amazonaws.com/{path_filename}'''


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

# login function
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def send_email(email, body):
    sender = SES_EMAIL_SOURCE
    if not sender:
        raise ValueError("SES_EMAIL_SOURCE environment variable is not set.")
    try:
        ses = boto3.client('ses', aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                           region_name=AWS_REGION)
        response = ses.send_email(
            Source=sender,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': 'Photo Gallery: Confirm Your Account'},
                'Body': {'Text': {'Data': body}}
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
        return False
    else:
        print("Email sent! Message ID:", response['MessageId'])
        return True

# s3 key function
def get_s3_key(url):
    parsed = urlparse(url)
    return parsed.path.lstrip('/')

"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""

# signup endpoint
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('name')
        password = request.form.get('password')
        password1 = request.form.get('password1')
        
        if not email or not full_name or not password or not password1:
            return "Please fill out all fields.", 400
        if password != password1:
            return "Passwords do not match.", 400
        
        names = full_name.strip().split(' ', 1)
        firstName = names[0]
        lastName = names[1] if len(names) > 1 else ''
        
        hashed_password = generate_password_hash(password)
        userID = str(uuid.uuid4())
        
        createdAt = datetime.now().astimezone().astimezone(pytz.utc).strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            user_table.put_item(
                Item={
                    "userID": userID,
                    "email": email,
                    "firstName": firstName,
                    "lastName": lastName,
                    "passwordHash": hashed_password,
                    "isVerified": False,
                    "createdAt": createdAt
                },
                ConditionExpression="attribute_not_exists(email)"
            )
        except Exception as e:
            return f"Error creating account: {str(e)}", 400
        
        token = serializer.dumps(email, salt=CONFIRM_EMAIL_SALT)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        email_body = f"Please confirm your email by clicking this link: {confirm_url}"
        
        if not send_email(email, email_body):
            return "Error: Unable to send confirmation email. Please check your SES configuration.", 400
        
        return "A confirmation email has been sent. Please check your inbox."
    else:
        return render_template('signup.html')

# confirm email endpoint
@app.route('/confirmemail/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt="email-confirm-salt", max_age=3600)
    except SignatureExpired:
        return "The confirmation link has expired.", 400
    except Exception as e:
        return "Invalid confirmation token.", 400

    try:
        user_table.update_item(
            Key={"email": email},
            UpdateExpression="SET isVerified = :val",
            ExpressionAttributeValues={":val": True}
        )
    except Exception as e:
        return f"Error updating user verification status: {str(e)}", 500

    return render_template('emailconfirmed.html')


# login endpoint
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            return "Please provide email and password.", 400
        
        response = user_table.get_item(Key={"email": email})
        user = response.get('Item')
        
        if user and check_password_hash(user['passwordHash'], password):
            if not user.get('isVerified', False):
                return "Your account is not verified. Please check your email.", 400
            session['user_id'] = user['userID']
            session['email'] = user['email']
            return redirect(url_for('home_page'))
        else:
            return "Invalid email or password.", 400
    else:
        return render_template('login.html')


# delete photo endpoint
@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['POST'])
@login_required
def delete_photo(albumID, photoID):
    try:
        response = photo_table.get_item(Key={'albumID': albumID, 'photoID': photoID})
    except Exception as e:
        print("Error retrieving photo item:", e)
        return "Error retrieving photo record", 500

    if 'Item' not in response:
        return "Photo not found", 404

    photo = response['Item']
    photoURL = photo.get('photoURL')
    if not photoURL:
        return "Photo URL not found", 400

    try:
        key = photoURL.split('.com/')[1]
    except IndexError:
        return "Invalid photo URL format", 400

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    try:
        s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=key)
    except Exception as e:
        print("Error deleting S3 object:", e)
        return "Error deleting photo from S3", 500

    try:
        photo_table.delete_item(Key={'albumID': albumID, 'photoID': photoID})
    except Exception as e:
        print("Error deleting DynamoDB item:", e)
        return "Error deleting photo record from database", 500

    return redirect(url_for('view_photos', albumID=albumID))


# delete album endpoint
@app.route('/album/<string:albumID>/delete', methods=['POST'])
@login_required
def delete_album(albumID):
    album_response = photo_table.query(
        KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail')
    )
    if not album_response['Items']:
        return "Album not found", 404

    album_meta = album_response['Items'][0]

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    thumb_url = album_meta.get('thumbnailURL')
    if thumb_url:
        try:
            thumb_key = thumb_url.split('.com/')[1]
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=thumb_key)
        except Exception as e:
            print("Error deleting album thumbnail from S3:", e)

    album_items_response = photo_table.query(
        KeyConditionExpression=Key('albumID').eq(albumID)
    )
    items = album_items_response.get('Items', [])

    for item in items:
        photo_url = item.get('photoURL')
        if photo_url:
            try:
                photo_key = photo_url.split('.com/')[1]
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=photo_key)
            except Exception as e:
                print("Error deleting photo from S3:", e)
        try:
            photo_table.delete_item(Key={'albumID': albumID, 'photoID': item['photoID']})
        except Exception as e:
            print("Error deleting item from DynamoDB:", e)

    return redirect(url_for('home_page'))


# delete user account endpoint
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    user_email = session.get('email')
    if not user_id or not user_email:
        return "User information missing from session.", 400

    try:
        user_table.delete_item(Key={"email": user_email})
    except Exception as e:
        return f"Error deleting user account: {str(e)}", 500

    try:
        response = photo_table.scan(FilterExpression=Attr('userID').eq(user_id))
        items = response.get('Items', [])
    except Exception as e:
        return f"Error scanning photo table: {str(e)}", 500

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    for item in items:
        photo_url = item.get('photoURL')
        if photo_url:
            try:
                key = get_s3_key(photo_url)
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=key)
            except Exception as e:
                print("Error deleting S3 object for photo:", e)
        try:
            album_id = item.get('albumID')
            photo_id = item.get('photoID')
            if album_id and photo_id:
                photo_table.delete_item(Key={'albumID': album_id, 'photoID': photo_id})
        except Exception as e:
            print("Error deleting photo record:", e)

    session.clear()
    return redirect(url_for('signup'))



# logout endpoint
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

"""
"""

@app.errorhandler(400)
def bad_request(error):
    """ 400 page route.

    get:
        description: Endpoint to return a bad request 400 page.
        responses: Returns 400 object.
    """
    return make_response(jsonify({'error': 'Bad request'}), 400)



@app.errorhandler(404)
def not_found(error):
    """ 404 page route.

    get:
        description: Endpoint to return a not found 404 page.
        responses: Returns 404 object.
    """
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/', methods=['GET'])
@login_required
def home_page():
    """ Home page route.

    get:
        description: Endpoint to return home page.
        responses: Returns all the albums.
    """
    response = photo_table.scan(FilterExpression=Attr('photoID').eq("thumbnail"))
    results = response['Items']

    if len(results) > 0:
        for index, value in enumerate(results):
            createdAt = datetime.strptime(str(results[index]['createdAt']), "%Y-%m-%d %H:%M:%S")
            createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
            results[index]['createdAt'] = createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")

    return render_template('index.html', albums=results)



@app.route('/createAlbum', methods=['GET', 'POST'])
@login_required
def add_album():
    """ Create new album route.

    get:
        description: Endpoint to return form to create a new album.
        responses: Returns all the fields needed to store new album.

    post:
        description: Endpoint to send new album.
        responses: Returns user to home page.
    """
    if request.method == 'POST':
        uploadedFileURL=''
        file = request.files['imagefile']
        name = request.form['name']
        description = request.form['description']

        if file and allowed_file(file.filename):
            albumID = uuid.uuid4()
            
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)
            
            uploadedFileURL = s3uploading(str(albumID), filenameWithPath, "thumbnails");

            createdAtlocalTime = datetime.now().astimezone()
            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)

            photo_table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": "thumbnail",
                    "name": name,
                    "description": description,
                    "thumbnailURL": uploadedFileURL,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "userID": session.get('user_id')
                }
            )

        return redirect('/')
    else:
        return render_template('albumForm.html')



@app.route('/album/<string:albumID>', methods=['GET'])
@login_required
def view_photos(albumID):
    """ Album page route.

    get:
        description: Endpoint to return an album.
        responses: Returns all the photos of a particular album.
    """
    albumResponse = photo_table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = photo_table.scan(FilterExpression=Attr('albumID').eq(albumID) & Attr('photoID').ne('thumbnail'))
    items = response['Items']

    return render_template('viewphotos.html', photos=items, albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/addPhoto', methods=['GET', 'POST'])
@login_required
def add_photo(albumID):
    """ Create new photo under album route.

    get:
        description: Endpoint to return form to create a new photo.
        responses: Returns all the fields needed to store a new photo.

    post:
        description: Endpoint to send new photo.
        responses: Returns user to album page.
    """
    if request.method == 'POST':    
        uploadedFileURL=''
        file = request.files['imagefile']
        title = request.form['title']
        description = request.form['description']
        tags = request.form['tags']
        if file and allowed_file(file.filename):
            photoID = uuid.uuid4()
            filename = file.filename
            filenameWithPath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filenameWithPath)            
            
            uploadedFileURL = s3uploading(filename, filenameWithPath);
            
            ExifData=getExifData(filenameWithPath)
            ExifDataStr = json.dumps(ExifData)

            createdAtlocalTime = datetime.now().astimezone()
            updatedAtlocalTime = datetime.now().astimezone()

            createdAtUTCTime = createdAtlocalTime.astimezone(pytz.utc)
            updatedAtUTCTime = updatedAtlocalTime.astimezone(pytz.utc)

            photo_table.put_item(
                Item={
                    "albumID": str(albumID),
                    "photoID": str(photoID),
                    "title": title,
                    "description": description,
                    "tags": tags,
                    "photoURL": uploadedFileURL,
                    "EXIF": ExifDataStr,
                    "createdAt": createdAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "updatedAt": updatedAtUTCTime.strftime("%Y-%m-%d %H:%M:%S"),
                    "userID": session.get('user_id')
                }
            )

        return redirect(f'''/album/{albumID}''')

    else:

        albumResponse = photo_table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
        albumMeta = albumResponse['Items']

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
@login_required
def view_photo(albumID, photoID):
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    albumResponse = photo_table.query(KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq('thumbnail'))
    albumMeta = albumResponse['Items']

    response = photo_table.query( KeyConditionExpression=Key('albumID').eq(albumID) & Key('photoID').eq(photoID))
    results = response['Items']

    if len(results) > 0:
        photo={}
        photo['photoID'] = results[0]['photoID']
        photo['title'] = results[0]['title']
        photo['description'] = results[0]['description']
        photo['tags'] = results[0]['tags']
        photo['photoURL'] = results[0]['photoURL']
        photo['EXIF']=json.loads(results[0]['EXIF'])

        createdAt = datetime.strptime(str(results[0]['createdAt']), "%Y-%m-%d %H:%M:%S")
        updatedAt = datetime.strptime(str(results[0]['updatedAt']), "%Y-%m-%d %H:%M:%S")

        createdAt_UTC = pytz.timezone("UTC").localize(createdAt)
        updatedAt_UTC = pytz.timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt']=updatedAt_UTC.astimezone(pytz.timezone("US/Eastern")).strftime("%B %d, %Y")
        
        tags=photo['tags'].split(',')
        exifdata=photo['EXIF']
        
        return render_template('photodetail.html', photo=photo, tags=tags, exifdata=exifdata, albumID=albumID, albumName=albumMeta[0]['name'])
    else:
        return render_template('photodetail.html', photo={}, tags=[], exifdata={}, albumID=albumID, albumName="")



@app.route('/album/search', methods=['GET'])
@login_required
def search_album_page():
    """ search album page route.

    get:
        description: Endpoint to return all the matching albums.
        responses: Returns all the albums based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = photo_table.scan(FilterExpression=Attr('name').contains(query) | Attr('description').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] == 'thumbnail':
            album={}
            album['albumID'] = item['albumID']
            album['name'] = item['name']
            album['description'] = item['description']
            album['thumbnailURL'] = item['thumbnailURL']
            items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
@login_required
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)    

    response = photo_table.scan(FilterExpression=Attr('title').contains(query) | Attr('description').contains(query) | Attr('tags').contains(query) | Attr('EXIF').contains(query))
    results = response['Items']

    items=[]
    for item in results:
        if item['photoID'] != 'thumbnail' and item['albumID'] == albumID:
            photo={}
            photo['photoID'] = item['photoID']
            photo['albumID'] = item['albumID']
            photo['title'] = item['title']
            photo['description'] = item['description']
            photo['photoURL'] = item['photoURL']
            items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
