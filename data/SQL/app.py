#!flask/bin/python
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'utils')))
from env import AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_REGION, PHOTOGALLERY_S3_BUCKET_NAME, RDS_DB_HOSTNAME, RDS_DB_USERNAME, RDS_DB_PASSWORD, RDS_DB_NAME, SECERT_KEY, CONFIRM_EMAIL_SALT, SES_EMAIL_SOURCE
from flask import Flask, jsonify, abort, request, make_response, url_for, render_template, redirect, session
import time
import exifread
import json
import uuid
import boto3  
import pymysql.cursors
from datetime import datetime
from pytz import timezone

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

def get_database_connection():
    conn = pymysql.connect(host=RDS_DB_HOSTNAME,
                             user=RDS_DB_USERNAME,
                             password=RDS_DB_PASSWORD,
                             db=RDS_DB_NAME,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)
    return conn

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


"""
    INSERT YOUR NEW FUNCTION HERE (IF NEEDED)
"""

# login functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# s3 key functions
def get_s3_key(url):
    parsed = urlparse(url)
    return parsed.path.lstrip('/')

"""
"""

"""
    INSERT YOUR NEW ROUTE HERE (IF NEEDED)
"""

# Signup endpoint
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
        
        conn = get_database_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO photogallerydb.User (userID, email, passwordHash, isVerified, firstName, lastName) VALUES (%s, %s, %s, %s, %s, %s)",
                (userID, email, hashed_password, False, firstName, lastName)
            )
            conn.commit()
        except Exception as e:
            conn.close()
            return f"Error creating account: {str(e)}", 400
        conn.close()
        
        token = serializer.dumps(email, salt=CONFIRM_EMAIL_SALT)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        email_body = f"Please confirm your email by clicking the following link: {confirm_url}"
        
        if not send_email(email, email_body):
            return "Error: Unable to send confirmation email. Please check your SES configuration.", 400
        
        return "A confirmation email has been sent. Please check your inbox."
    else:
        return render_template('signup.html')


# confirm email endpoint
@app.route('/confirmemail/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt=CONFIRM_EMAIL_SALT, max_age=3600)
    except SignatureExpired:
        return "The confirmation link has expired.", 400
    except Exception as e:
        return "Invalid confirmation token.", 400

    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE photogallerydb.User SET isVerified = TRUE WHERE email = %s", (email,))
    conn.commit()
    conn.close()
    
    return render_template('emailconfirmed.html')


# login endpoint
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            return "Please provide email and password.", 400
        
        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM photogallerydb.User WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['passwordHash'], password):
            if not user['isVerified']:
                return "Your account is not verified. Please check your email.", 400
            session['user_id'] = user['userID']
            session['email'] = user['email']
            return redirect('/')
        else:
            return "Invalid email or password.", 400
    else:
        return render_template('login.html')


# logout endpoint
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# delete photo endpoint
@app.route('/album/<string:albumID>/photo/<string:photoID>/delete', methods=['POST'])
@login_required
def delete_photo(albumID, photoID):
    conn = get_database_connection()
    cursor = conn.cursor()

    statement = "SELECT photoURL FROM photogallerydb.Photo WHERE photoID = %s AND albumID = %s"
    cursor.execute(statement, (photoID, albumID))
    result = cursor.fetchone()
    if not result:
        conn.close()
        return "Photo not found", 404

    photoURL = result['photoURL']

    try:
        key = photoURL.split('.com/')[1]
    except IndexError:
        conn.close()
        return "Invalid photo URL format.", 400

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    try:
        s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=key)
    except Exception as e:
        print("Error deleting S3 object:", e)
        conn.close()
        return "Error deleting photo from S3", 500

    delete_statement = "DELETE FROM photogallerydb.Photo WHERE photoID = %s AND albumID = %s"
    cursor.execute(delete_statement, (photoID, albumID))
    conn.commit()
    conn.close()

    return redirect(url_for('view_photos', albumID=albumID))


# delete album
@app.route('/album/<string:albumID>/delete', methods=['POST'])
@login_required
def delete_album(albumID):
    conn = get_database_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM photogallerydb.Album WHERE albumID = %s", (albumID,))
    album = cursor.fetchone()
    if not album:
        conn.close()
        return "Album not found", 404

    cursor.execute("SELECT photoID, photoURL FROM photogallerydb.Photo WHERE albumID = %s", (albumID,))
    photos = cursor.fetchall()

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                           aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    album_thumbnail_url = album['thumbnailURL']

    try:
        thumbnail_key = album_thumbnail_url.split('.com/')[1]
        s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=thumbnail_key)
    except Exception as e:
        print("Error deleting album thumbnail from S3:", e)

    for photo in photos:
        photo_url = photo['photoURL']
        try:
            photo_key = photo_url.split('.com/')[1]
            s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=photo_key)
        except Exception as e:
            print("Error deleting photo from S3:", e)

    try:
        cursor.execute("DELETE FROM photogallerydb.Album WHERE albumID = %s", (albumID,))
        conn.commit()
    except Exception as e:
        conn.close()
        return "Error deleting album from database: " + str(e), 500

    conn.close()
    return redirect(url_for('home_page'))


# delete account endpoint
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    if not user_id:
        return "User information missing from session.", 400

    conn = get_database_connection()
    cursor = conn.cursor()

    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    try:
        cursor.execute("SELECT albumID, thumbnailURL FROM photogallerydb.Album WHERE userID = %s", (user_id,))
        albums = cursor.fetchall()
    except Exception as e:
        conn.close()
        return f"Error retrieving albums: {str(e)}", 500

    for album in albums:
        album_id = album['albumID']
        thumbnail_url = album.get('thumbnailURL')
        if thumbnail_url:
            try:
                thumb_key = get_s3_key(thumbnail_url)
                s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=thumb_key)
            except Exception as e:
                print("Error deleting album thumbnail from S3:", e)
        try:
            cursor.execute("SELECT photoID, photoURL FROM photogallerydb.Photo WHERE albumID = %s", (album_id,))
            photos = cursor.fetchall()
            for photo in photos:
                photo_url = photo.get('photoURL')
                if photo_url:
                    try:
                        photo_key = get_s3_key(photo_url)
                        s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=photo_key)
                    except Exception as e:
                        print("Error deleting photo from S3:", e)
                try:
                    cursor.execute("DELETE FROM photogallerydb.Photo WHERE photoID = %s AND albumID = %s", (photo['photoID'], album_id))
                except Exception as e:
                    print("Error deleting photo record:", e)
            conn.commit()
        except Exception as e:
            print("Error processing photos in album:", e)

        try:
            cursor.execute("DELETE FROM photogallerydb.Album WHERE albumID = %s", (album_id,))
            conn.commit()
        except Exception as e:
            print("Error deleting album record:", e)

    try:
        cursor.execute("SELECT photoID, albumID, photoURL FROM photogallerydb.Photo WHERE userID = %s", (user_id,))
        orphan_photos = cursor.fetchall()
        for photo in orphan_photos:
            photo_url = photo.get('photoURL')
            if photo_url:
                try:
                    photo_key = get_s3_key(photo_url)
                    s3.delete_object(Bucket=PHOTOGALLERY_S3_BUCKET_NAME, Key=photo_key)
                except Exception as e:
                    print("Error deleting orphan photo from S3:", e)
            try:
                cursor.execute("DELETE FROM photogallerydb.Photo WHERE photoID = %s AND albumID = %s", (photo['photoID'], photo['albumID']))
            except Exception as e:
                print("Error deleting orphan photo record:", e)
            conn.commit()
    except Exception as e:
        print("Error processing orphan photos:", e)

    try:
        cursor.execute("DELETE FROM photogallerydb.User WHERE userID = %s", (user_id,))
        conn.commit()
    except Exception as e:
        conn.close()
        return f"Error deleting user account: {str(e)}", 500

    cursor.close()
    conn.close()
    
    session.clear()
    return redirect(url_for('signup'))


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
    conn=get_database_connection()
    cursor = conn.cursor ()
    cursor.execute("SELECT * FROM photogallerydb.Album;")
    results = cursor.fetchall()
    conn.close()
    
    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']

        createdAt = datetime.strptime(str(item['createdAt']), "%Y-%m-%d %H:%M:%S")
        createdAt_UTC = timezone("UTC").localize(createdAt)
        album['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")

        items.append(album)

    return render_template('index.html', albums=items)



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

            conn=get_database_connection()
            cursor = conn.cursor ()
            statement = '''INSERT INTO photogallerydb.Album (albumID, name, description, thumbnailURL, userID) VALUES (%s, %s, %s, %s, %s);'''

            result = cursor.execute(statement, (albumID, name, description, uploadedFileURL, session['user_id']))
            conn.commit()
            conn.close()

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
    conn=get_database_connection()
    cursor = conn.cursor ()
    # Get title
    statement = '''SELECT * FROM photogallerydb.Album WHERE albumID=%s;'''
    cursor.execute(statement, (albumID,))
    albumMeta = cursor.fetchall()
    
    # Photos
    statement = '''SELECT photoID, albumID, title, description, photoURL FROM photogallerydb.Photo WHERE albumID=%s;'''
    cursor.execute(statement, (albumID,))
    results = cursor.fetchall()
    conn.close() 
    
    items=[]
    for item in results:
        photos={}
        photos['photoID'] = item['photoID']
        photos['albumID'] = item['albumID']
        photos['title'] = item['title']
        photos['description'] = item['description']
        photos['photoURL'] = item['photoURL']
        items.append(photos)

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
            
            uploadedFileURL = s3uploading(filename, filenameWithPath)
            
            ExifData=getExifData(filenameWithPath)

            conn=get_database_connection()
            cursor = conn.cursor ()
            ExifDataStr = json.dumps(ExifData)
            statement = '''INSERT INTO photogallerydb.Photo (PhotoID, albumID, title, description, tags, photoURL, EXIF, userID) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);'''

            result = cursor.execute(statement, (photoID, albumID, title, description, tags, uploadedFileURL, ExifDataStr, session['user_id']))
            conn.commit()
            conn.close()

        return redirect(f'''/album/{albumID}''')
    else:
        conn=get_database_connection()
        cursor = conn.cursor ()
        # Get title
        statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID=%s;'''
        cursor.execute(statement, (albumID,))
        albumMeta = cursor.fetchall()
        conn.close()

        return render_template('photoForm.html', albumID=albumID, albumName=albumMeta[0]['name'])



@app.route('/album/<string:albumID>/photo/<string:photoID>', methods=['GET'])
@login_required
def view_photo(albumID, photoID):  
    """ photo page route.

    get:
        description: Endpoint to return a photo.
        responses: Returns a photo from a particular album.
    """ 
    conn=get_database_connection()
    cursor = conn.cursor ()

    # Get title
    statement = f'''SELECT * FROM photogallerydb.Album WHERE albumID=%s;'''
    cursor.execute(statement, (albumID,))
    albumMeta = cursor.fetchall()

    statement = f'''SELECT * FROM photogallerydb.Photo WHERE albumID=%s and photoID=%s;'''
    cursor.execute(statement, (albumID, photoID))
    results = cursor.fetchall()
    conn.close()

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

        createdAt_UTC = timezone("UTC").localize(createdAt)
        updatedAt_UTC = timezone("UTC").localize(updatedAt)

        photo['createdAt']=createdAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
        photo['updatedAt']=updatedAt_UTC.astimezone(timezone("US/Eastern")).strftime("%B %d, %Y")
        
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
    original_query = query
    query = '%' + query + '%'

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Album WHERE name LIKE %s UNION SELECT * FROM photogallerydb.Album WHERE description LIKE %s;'''
    cursor.execute(statement, (query, query))

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        album={}
        album['albumID'] = item['albumID']
        album['name'] = item['name']
        album['description'] = item['description']
        album['thumbnailURL'] = item['thumbnailURL']
        items.append(album)

    return render_template('searchAlbum.html', albums=items, searchquery=original_query)



@app.route('/album/<string:albumID>/search', methods=['GET'])
@login_required
def search_photo_page(albumID):
    """ search photo page route.

    get:
        description: Endpoint to return all the matching photos.
        responses: Returns all the photos from an album based on a particular query.
    """ 
    query = request.args.get('query', None)
    original_query = query
    query = '%'+query+'%'

    conn=get_database_connection()
    cursor = conn.cursor ()
    statement = f'''SELECT * FROM photogallerydb.Photo WHERE title LIKE %s AND albumID=%s 
                    UNION SELECT * FROM photogallerydb.Photo WHERE description LIKE %s AND albumID=%s 
                    UNION SELECT * FROM photogallerydb.Photo WHERE tags LIKE %s AND albumID=%s
                    UNION SELECT * FROM photogallerydb.Photo WHERE EXIF LIKE %s AND albumID=%s;'''
    cursor.execute(statement, (query, albumID, query, albumID, query, albumID, query, albumID, ))

    results = cursor.fetchall()
    conn.close()

    items=[]
    for item in results:
        photo={}
        photo['photoID'] = item['photoID']
        photo['albumID'] = item['albumID']
        photo['title'] = item['title']
        photo['description'] = item['description']
        photo['photoURL'] = item['photoURL']
        items.append(photo)

    return render_template('searchPhoto.html', photos=items, searchquery=original_query, albumID=albumID)



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
