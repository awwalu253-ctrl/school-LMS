from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import os
import json
from datetime import datetime
import time
from functools import wraps

app = Flask(__name__, static_folder='.')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

CORS(app, supports_credentials=True, 
     origins=['http://localhost:5000', 'http://127.0.0.1:5000'],
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     expose_headers=['Set-Cookie'])

DATABASE = 'lms_database.db'

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'teacher':
            return jsonify({'error': 'Teacher access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'student':
            return jsonify({'error': 'Student access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        
        # Users table
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            role TEXT NOT NULL,
            teacher_code TEXT UNIQUE,
            specialization TEXT,
            phone TEXT,
            address TEXT,
            date_of_birth TEXT,
            gender TEXT,
            student_id TEXT,
            department TEXT,
            level TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Courses table
        db.execute('''CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            course_code TEXT UNIQUE,
            credits INTEGER,
            teacher_lock BOOLEAN DEFAULT 1,
            status TEXT DEFAULT 'active',
            level TEXT DEFAULT 'all',
            department TEXT DEFAULT 'all',
            is_compulsory BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Teacher-Course assignments table
        db.execute('''CREATE TABLE IF NOT EXISTS teacher_courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            course_id INTEGER,
            assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
            UNIQUE(teacher_id, course_id)
        )''')
        
        # Enrollments table
        db.execute('''CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            course_id INTEGER,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
            UNIQUE(student_id, course_id)
        )''')
        
        # Announcements table
        db.execute('''CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER,
            teacher_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id),
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )''')
        
        # Assignments table
        db.execute('''CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER,
            teacher_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            due_date TIMESTAMP,
            max_points INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id),
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )''')
        
        # Submissions table
        db.execute('''CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER,
            student_id INTEGER,
            content TEXT,
            file_url TEXT,
            grade INTEGER,
            feedback TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assignment_id) REFERENCES assignments(id),
            FOREIGN KEY (student_id) REFERENCES users(id),
            UNIQUE(assignment_id, student_id)
        )''')
        
        # Materials table
        db.execute('''CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER,
            teacher_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            file_url TEXT,
            material_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id),
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )''')
        
        # Discussion posts table
        db.execute('''CREATE TABLE IF NOT EXISTS discussion_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (course_id) REFERENCES courses(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        # Discussion replies table
        db.execute('''CREATE TABLE IF NOT EXISTS discussion_replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES discussion_posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')
        
        # Notifications table
        db.execute('''CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL,
            reference_id INTEGER,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # Admin announcements table
        db.execute('''CREATE TABLE IF NOT EXISTS admin_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users(id)
        )''')
        
        # Course approval requests table
        db.execute('''CREATE TABLE IF NOT EXISTS course_approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER,
            course_id INTEGER,
            admin_id INTEGER,
            status TEXT DEFAULT 'pending',
            admin_notes TEXT,
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMP,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
            FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
        )''')
        
        # Create indexes
        try:
            db.execute('''CREATE INDEX IF NOT EXISTS idx_courses_level_department 
                          ON courses(level, department)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_course_approval_requests_status 
                          ON course_approval_requests(status)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_course_approval_requests_teacher 
                          ON course_approval_requests(teacher_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_course_approval_requests_course 
                          ON course_approval_requests(course_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_teacher_courses_teacher 
                          ON teacher_courses(teacher_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_teacher_courses_course 
                          ON teacher_courses(course_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_notifications_user 
                          ON notifications(user_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_enrollments_student 
                          ON enrollments(student_id)''')
            db.execute('''CREATE INDEX IF NOT EXISTS idx_enrollments_course 
                          ON enrollments(course_id)''')
            db.commit()
        except Exception as e:
            print(f"⚠️ Error creating indexes: {e}")
            db.rollback()
        
        # Create admin user if not exists
        admin_exists = db.execute('SELECT * FROM users WHERE email = ?', 
                                 ('admin@school.edu',)).fetchone()
        if not admin_exists:
            try:
                db.execute('''INSERT INTO users (email, password, first_name, last_name, role)
                             VALUES (?, ?, ?, ?, ?)''',
                          ('admin@school.edu', generate_password_hash('admin123'), 
                           'System', 'Administrator', 'admin'))
                db.commit()
                print("✅ Admin user created")
            except Exception as e:
                print(f"⚠️ Could not create admin user: {e}")
        
        # Create teacher user if not exists
        teacher_exists = db.execute('SELECT * FROM users WHERE email = ?', 
                                   ('teacher@school.edu',)).fetchone()
        if not teacher_exists:
            try:
                db.execute('''INSERT INTO users (email, password, first_name, last_name, role, teacher_code)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          ('teacher@school.edu', generate_password_hash('teacher123'), 
                           'John', 'Doe', 'teacher', 'TCH001'))
                db.commit()
                print("✅ Teacher user created")
            except Exception as e:
                print(f"⚠️ Could not create teacher user: {e}")
        
        # Create initial courses with compulsory subjects for each level
        try:
            course_count = db.execute('SELECT COUNT(*) as count FROM courses').fetchone()['count']
            if course_count == 0:
                # Compulsory courses definitions for each level
                compulsory_courses_config = {
                    'MS1': [
                        ('Mathematics MS1', 'Mathematics for Middle School 1', 'MATH-MS1', 3, 'all', 'MS1', 1),
                        ('English Language MS1', 'English Language for Middle School 1', 'ENG-MS1', 3, 'all', 'MS1', 1),
                        ('Data Processing MS1', 'Data Processing for Middle School 1', 'DATA-PROC-MS1', 3, 'all', 'MS1', 1)
                    ],
                    'MS2': [
                        ('Mathematics MS2', 'Mathematics for Middle School 2', 'MATH-MS2', 3, 'all', 'MS2', 1),
                        ('English Language MS2', 'English Language for Middle School 2', 'ENG-MS2', 3, 'all', 'MS2', 1),
                        ('Data Processing MS2', 'Data Processing for Middle School 2', 'DATA-PROC-MS2', 3, 'all', 'MS2', 1)
                    ],
                    'MS3': [
                        ('Mathematics MS3', 'Mathematics for Middle School 3', 'MATH-MS3', 3, 'all', 'MS3', 1),
                        ('English Language MS3', 'English Language for Middle School 3', 'ENG-MS3', 3, 'all', 'MS3', 1),
                        ('Data Processing MS3', 'Data Processing for Middle School 3', 'DATA-PROC-MS3', 3, 'all', 'MS3', 1)
                    ],
                    'HS1': [
                        ('Mathematics HS1', 'Mathematics for High School 1', 'MATH-HS1', 3, 'all', 'HS1', 1),
                        ('English Language HS1', 'English Language for High School 1', 'ENG-HS1', 3, 'all', 'HS1', 1),
                        ('Data Processing HS1', 'Data Processing for High School 1', 'DATA-PROC-HS1', 3, 'all', 'HS1', 1)
                    ],
                    'HS2': [
                        ('Mathematics HS2', 'Mathematics for High School 2', 'MATH-HS2', 3, 'all', 'HS2', 1),
                        ('English Language HS2', 'English Language for High School 2', 'ENG-HS2', 3, 'all', 'HS2', 1),
                        ('Data Processing HS2', 'Data Processing for High School 2', 'DATA-PROC-HS2', 3, 'all', 'HS2', 1)
                    ],
                    'HS3': [
                        ('Mathematics HS3', 'Mathematics for High School 3', 'MATH-HS3', 3, 'all', 'HS3', 1),
                        ('English Language HS3', 'English Language for High School 3', 'ENG-HS3', 3, 'all', 'HS3', 1),
                        ('Data Processing HS3', 'Data Processing for High School 3', 'DATA-PROC-HS3', 3, 'all', 'HS3', 1)
                    ]
                }
                
                # Insert compulsory courses for each level
                for level, courses in compulsory_courses_config.items():
                    for title, description, code, credits, department, level_name, is_compulsory in courses:
                        db.execute('''INSERT INTO courses (title, description, course_code, credits, teacher_lock, 
                                     level, department, is_compulsory)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                  (title, description, code, credits, 1, level_name, department, is_compulsory))
                
                db.commit()
                print("✅ Database initialized with compulsory courses for each level!")
        except Exception as e:
            print(f"⚠️ Error creating courses: {e}")

# Serve the main page
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Authentication routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        db = get_db()
        
        # Validate department requirement for HS students
        if data['role'] == 'student':
            level = data.get('level', '')
            department = data.get('department', '')
            
            if level.startswith('HS') and not department:
                return jsonify({'error': 'Department is required for High School students'}), 400
            
            # Generate student ID
            data['student_id'] = generate_student_id(db)
        
        if data['role'] == 'teacher':
            # Check if teacher code already exists
            existing_code = db.execute('SELECT * FROM users WHERE teacher_code = ?', 
                                      (data.get('teacher_code'),)).fetchone()
            if existing_code:
                return jsonify({'error': 'Teacher code already exists'}), 400
        
        hashed_password = generate_password_hash(data['password'])
        
        # Insert user
        cursor = db.execute('''INSERT INTO users (email, password, first_name, last_name, role,
                            student_id, phone, address, date_of_birth, gender, department, level,
                            teacher_code, specialization)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (data['email'], hashed_password, data['first_name'], 
                   data['last_name'], data['role'],
                   data.get('student_id'), data.get('phone'), data.get('address'), 
                   data.get('date_of_birth'), data.get('gender'), 
                   data.get('department'), data.get('level'),
                   data.get('teacher_code'), data.get('specialization')))
        db.commit()
        
        # Get the created user
        new_user_id = cursor.lastrowid
        user = db.execute('SELECT * FROM users WHERE id = ?', (new_user_id,)).fetchone()
        
        # Auto-enroll student in compulsory courses
        if data['role'] == 'student':
            auto_enroll_compulsory_courses(db, new_user_id, data.get('level'), data.get('department'))
        
        return jsonify({
            'message': 'Registration successful',
            'student_id': user['student_id'] if data['role'] == 'student' else None,
            'user_id': user['id']
        }), 201
    except sqlite3.IntegrityError as e:
        if 'email' in str(e):
            return jsonify({'error': 'Email already exists'}), 400
        elif 'teacher_code' in str(e):
            return jsonify({'error': 'Teacher code already exists'}), 400
        return jsonify({'error': 'Registration failed'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

def generate_student_id(db):
    """Generate next student ID in sequence LMS001, LMS002, etc."""
    try:
        students = db.execute('''SELECT student_id FROM users 
                               WHERE role = "student" AND student_id LIKE "LMS%" 
                               ORDER BY student_id''').fetchall()
        
        if not students:
            return "LMS001"
        
        max_number = 0
        for student in students:
            if student['student_id'] and student['student_id'].startswith('LMS'):
                try:
                    number_part = student['student_id'][3:]
                    num = int(number_part)
                    if num > max_number:
                        max_number = num
                except ValueError:
                    continue
        
        next_number = max_number + 1
        return f"LMS{next_number:03d}"
        
    except Exception as e:
        import time
        timestamp = int(time.time() % 1000)
        return f"LMS{timestamp:03d}"

def auto_enroll_compulsory_courses(db, student_id, level, department=None):
    """Auto-enroll student in compulsory courses for their level"""
    try:
        # Get student info
        student = db.execute('SELECT * FROM users WHERE id = ?', (student_id,)).fetchone()
        if not student:
            return
        
        # Get compulsory courses for the student's specific level
        compulsory_courses = db.execute('''SELECT id FROM courses 
                                        WHERE level = ? AND is_compulsory = 1 AND status = 'active' ''',
                                      (level,)).fetchall()
        
        for course in compulsory_courses:
            try:
                db.execute('''INSERT INTO enrollments (student_id, course_id)
                             VALUES (?, ?)''', (student_id, course['id']))
                print(f"✅ Auto-enrolled student {student_id} in compulsory course {course['id']} for level {level}")
            except sqlite3.IntegrityError:
                pass  # Already enrolled
        
        db.commit()
        
        print(f"✅ Auto-enrolled student {student_id} in {len(compulsory_courses)} compulsory courses for level {level}")
        
    except Exception as e:
        print(f"⚠️ Error auto-enrolling student: {e}")

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT'])
@login_required
def user_profile(user_id):
    if session['user_id'] != user_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    db = get_db()
    
    if request.method == 'GET':
        try:
            user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            if user:
                user_dict = dict(user)
                user_dict.pop('password', None)
                return jsonify(user_dict)
            return jsonify({'error': 'User not found'}), 404
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.json
            if 'password' in data:
                data['password'] = generate_password_hash(data['password'])
            
            update_fields = []
            update_values = []
            
            for field in ['first_name', 'last_name', 'phone', 'address', 'date_of_birth', 
                         'gender', 'department', 'level', 'specialization', 'password']:
                if field in data:
                    update_fields.append(f"{field} = ?")
                    update_values.append(data[field])
            
            if update_fields:
                update_values.append(user_id)
                query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
                db.execute(query, update_values)
                db.commit()
            
            return jsonify({'message': 'Profile updated'})
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        db = get_db()
        
        user = db.execute('SELECT * FROM users WHERE email = ?', 
                         (data['email'],)).fetchone()
        
        if user and check_password_hash(user['password'], data['password']):
            if user['status'] == 'suspended':
                return jsonify({'error': 'Your account has been suspended. Please contact administrator.'}), 403
            
            if data.get('role') == 'student' and user['role'] != 'student':
                return jsonify({'error': 'Invalid student account'}), 401
            
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role']
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/teacher-login', methods=['POST'])
def teacher_login():
    try:
        data = request.json
        db = get_db()
        
        user = db.execute('SELECT * FROM users WHERE email = ? AND role = "teacher"', 
                         (data['email'],)).fetchone()
        
        if user and check_password_hash(user['password'], data['password']):
            if user['status'] == 'suspended':
                return jsonify({'error': 'Your account has been suspended. Please contact administrator.'}), 403
            
            if user['teacher_code'] != data.get('teacher_code'):
                return jsonify({'error': 'Invalid teacher code'}), 401
            
            # Get assigned courses
            courses = db.execute('''SELECT c.* FROM courses c
                                   JOIN teacher_courses tc ON c.id = tc.course_id
                                   WHERE tc.teacher_id = ?''', (user['id'],)).fetchall()
            
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role'],
                'teacher_code': user['teacher_code'],
                'teacher_id': user['id'],
                'assigned_courses': [dict(course) for course in courses]
            })
        
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        db = get_db()
        
        user = db.execute('SELECT * FROM users WHERE email = ? AND role = "admin"', 
                         (data['email'],)).fetchone()
        
        if user and check_password_hash(user['password'], data['password']):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
            return jsonify({
                'id': user['id'],
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'role': user['role']
            })
        
        return jsonify({'error': 'Invalid admin credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/check-session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'user_id': session['user_id'],
            'role': session.get('role')
        })
    return jsonify({'logged_in': False})

# Course routes
@app.route('/api/courses', methods=['GET', 'POST'])
@login_required
def courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            user_id = session['user_id']
            user_role = session.get('role')
            
            # Get student's level and department for filtering
            student_info = None
            if user_role == 'student':
                student = db.execute('SELECT level, department FROM users WHERE id = ?', 
                                    (user_id,)).fetchone()
                if student:
                    student_info = dict(student)
            
            # Build query based on user role
            if user_role == 'student' and student_info:
                level = student_info['level']
                department = student_info['department']
                
                if level.startswith('MS'):
                    query = '''SELECT c.*, 
                              GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                              FROM courses c
                              LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                              LEFT JOIN users u ON tc.teacher_id = u.id
                              WHERE c.status = 'active' 
                              AND (c.level = ? OR c.level = 'all')
                              AND (c.department = 'all')
                              GROUP BY c.id
                              ORDER BY c.title'''
                    params = [level]
                elif level.startswith('HS') and department:
                    query = '''SELECT c.*, 
                              GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                              FROM courses c
                              LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                              LEFT JOIN users u ON tc.teacher_id = u.id
                              WHERE c.status = 'active' 
                              AND (c.level = ? OR c.level = 'all')
                              AND (c.department = ? OR c.department = 'all')
                              GROUP BY c.id
                              ORDER BY c.title'''
                    params = [level, department]
                else:
                    query = '''SELECT c.*, 
                              GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                              FROM courses c
                              LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                              LEFT JOIN users u ON tc.teacher_id = u.id
                              WHERE c.status = 'active'
                              GROUP BY c.id
                              ORDER BY c.title'''
                    params = []
            else:
                query = '''SELECT c.*, 
                          GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                          FROM courses c
                          LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                          LEFT JOIN users u ON tc.teacher_id = u.id
                          WHERE c.status = 'active'
                          GROUP BY c.id
                          ORDER BY c.title'''
                params = []
            
            courses_data = db.execute(query, params).fetchall()
            return jsonify([dict(course) for course in courses_data])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            db.execute('''INSERT INTO courses (title, description, course_code, credits, teacher_lock,
                         level, department, is_compulsory)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (data['title'], data['description'], 
                       data['course_code'], data['credits'], data.get('teacher_lock', 1),
                       data.get('level', 'all'), data.get('department', 'all'), 
                       data.get('is_compulsory', 0)))
            course_id = db.lastrowid
            
            if data.get('teacher_id'):
                db.execute('INSERT INTO teacher_courses (teacher_id, course_id) VALUES (?, ?)',
                          (data['teacher_id'], course_id))
            
            db.commit()
            return jsonify({'message': 'Course created', 'id': course_id}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Course code already exists'}), 400
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/courses/for-teacher', methods=['GET'])
@teacher_required
def get_courses_for_teacher():
    """Get courses filtered by teacher's department"""
    try:
        db = get_db()
        teacher_id = session['user_id']
        
        # Get teacher's department
        teacher = db.execute('SELECT department FROM users WHERE id = ?', (teacher_id,)).fetchone()
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        teacher_department = teacher['department']
        
        # Get courses that match teacher's department OR are general (department = 'all')
        courses = db.execute('''SELECT c.*, 
                              GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names,
                              CASE 
                                  WHEN tc.teacher_id IS NOT NULL THEN 1 
                                  ELSE 0 
                              END as is_assigned
                              FROM courses c
                              LEFT JOIN teacher_courses tc ON c.id = tc.course_id AND tc.teacher_id = ?
                              LEFT JOIN users u ON tc.teacher_id = u.id
                              WHERE c.status = 'active' 
                              AND (c.department = ? OR c.department = 'all')
                              GROUP BY c.id
                              ORDER BY c.title''', (teacher_id, teacher_department)).fetchall()
        
        return jsonify([dict(course) for course in courses])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/courses/by-level-department', methods=['GET'])
@login_required
def get_courses_by_level_department():
    try:
        level = request.args.get('level', '')
        department = request.args.get('department', '')
        
        db = get_db()
        
        query = '''SELECT c.*, 
                  GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                  FROM courses c
                  LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                  LEFT JOIN users u ON tc.teacher_id = u.id
                  WHERE c.status = 'active' '''
        
        params = []
        
        if level:
            query += ' AND (c.level = ? OR c.level = "all") '
            params.append(level)
        
        if department:
            query += ' AND (c.department = ? OR c.department = "all") '
            params.append(department)
        
        query += ' GROUP BY c.id ORDER BY c.title'
        
        courses = db.execute(query, params).fetchall()
        return jsonify([dict(course) for course in courses])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/students/by-level-department', methods=['GET'])
@login_required
def get_students_by_level_department():
    try:
        level = request.args.get('level', '')
        department = request.args.get('department', '')
        
        db = get_db()
        
        query = '''SELECT id, first_name, last_name, email, student_id, 
                  phone, department, level, status, created_at
                  FROM users WHERE role = "student" '''
        
        params = []
        
        if level:
            query += ' AND level = ? '
            params.append(level)
        
        if department:
            query += ' AND department = ? '
            params.append(department)
        
        query += ' ORDER BY last_name, first_name'
        
        students = db.execute(query, params).fetchall()
        return jsonify([dict(student) for student in students])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Teacher course assignment routes
@app.route('/api/teachers/<int:teacher_id>/courses', methods=['GET'])
@login_required
def teacher_courses_list(teacher_id):
    if session['user_id'] != teacher_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        courses = db.execute('''SELECT c.* FROM courses c
                               JOIN teacher_courses tc ON c.id = tc.course_id
                               WHERE tc.teacher_id = ?
                               ORDER BY c.title''', (teacher_id,)).fetchall()
        return jsonify([dict(course) for course in courses])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/teachers/<int:teacher_id>/assign-course', methods=['POST'])
@login_required
def assign_course_to_teacher(teacher_id):
    if session['user_id'] != teacher_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.json
        db = get_db()
        
        course = db.execute('SELECT * FROM courses WHERE id = ?', (data['course_id'],)).fetchone()
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        teacher = db.execute('SELECT * FROM users WHERE id = ? AND role = "teacher"', 
                           (teacher_id,)).fetchone()
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        existing = db.execute('''SELECT * FROM teacher_courses 
                                WHERE teacher_id = ? AND course_id = ?''',
                             (teacher_id, data['course_id'])).fetchone()
        if existing:
            return jsonify({'error': 'You are already teaching this course'}), 400
        
        # For admin direct assignment
        if session.get('role') == 'admin':
            db.execute('''INSERT INTO teacher_courses (teacher_id, course_id)
                         VALUES (?, ?)''', (teacher_id, data['course_id']))
            db.commit()
            return jsonify({'message': 'Course assigned successfully'}), 201
        
        # Check for pending request
        pending_request = db.execute('''SELECT * FROM course_approval_requests 
                                       WHERE teacher_id = ? AND course_id = ? 
                                       AND status = "pending"''',
                                    (teacher_id, data['course_id'])).fetchone()
        if pending_request:
            return jsonify({'error': 'You already have a pending request for this course'}), 400
        
        # Create approval request
        db.execute('''INSERT INTO course_approval_requests 
                    (teacher_id, course_id, status)
                    VALUES (?, ?, ?)''',
                  (teacher_id, data['course_id'], 'pending'))
        
        # Create notification for all admins
        admins = db.execute('SELECT id FROM users WHERE role = "admin"').fetchall()
        for admin in admins:
            db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                         VALUES (?, ?, ?, ?, ?)''',
                      (admin['id'], 'Course Approval Request',
                       f"Teacher {teacher['first_name']} {teacher['last_name']} wants to teach {course['title']}",
                       'approval', data['course_id']))
        
        db.commit()
        
        return jsonify({
            'message': 'Course approval request submitted. An admin will review your request.',
            'requires_approval': True
        }), 200
        
    except sqlite3.IntegrityError as e:
        db.rollback()
        return jsonify({'error': 'Database error: ' + str(e)}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
@app.route('/api/teachers/<int:teacher_id>/unassign-course/<int:course_id>', methods=['DELETE'])
@login_required
def unassign_course_from_teacher(teacher_id, course_id):
    if session['user_id'] != teacher_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        db.execute('DELETE FROM teacher_courses WHERE teacher_id = ? AND course_id = ?',
                  (teacher_id, course_id))
        db.commit()
        return jsonify({'message': 'Course unassigned successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>', methods=['GET'])
@login_required
def get_course(course_id):
    try:
        db = get_db()
        course = db.execute('''SELECT c.*, 
                              GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                              FROM courses c
                              LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                              LEFT JOIN users u ON tc.teacher_id = u.id
                              WHERE c.id = ?
                              GROUP BY c.id''', (course_id,)).fetchone()
        return jsonify(dict(course)) if course else ('', 404)
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/courses/<int:course_id>/students', methods=['GET'])
@login_required
def get_course_students(course_id):
    try:
        db = get_db()
        students = db.execute('''SELECT u.id, u.first_name, u.last_name, u.email, u.phone, 
                                u.address, u.date_of_birth, u.gender, u.student_id, 
                                u.department, u.level, e.enrolled_at
                                FROM users u
                                JOIN enrollments e ON u.id = e.student_id
                                WHERE e.course_id = ? AND u.status = 'active'
                                ORDER BY u.last_name, u.first_name''', (course_id,)).fetchall()
        return jsonify([dict(student) for student in students])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Enrollment routes
@app.route('/api/enroll', methods=['POST'])
@login_required
def enroll():
    try:
        data = request.json
        
        if session.get('role') != 'student':
            return jsonify({'error': 'Only students can enroll in courses'}), 403
        
        data['student_id'] = session['user_id']
        
        db = get_db()
        
        student = db.execute('SELECT level, department FROM users WHERE id = ?',
                           (data['student_id'],)).fetchone()
        course = db.execute('SELECT level, department FROM courses WHERE id = ?',
                          (data['course_id'],)).fetchone()
        
        if not student or not course:
            return jsonify({'error': 'Invalid student or course'}), 404
        
        # Check course eligibility
        if (course['level'] != 'all' and course['level'] != student['level'] and 
            not (student['level'].startswith('MS') and course['level'].startswith('MS')) and
            not (student['level'].startswith('HS') and course['level'].startswith('HS'))):
            return jsonify({'error': 'Course not available for your level'}), 400
        
        if (course['department'] != 'all' and course['department'] != student['department'] and
            student['level'].startswith('HS')):
            return jsonify({'error': 'Course not available for your department'}), 400
        
        db.execute('''INSERT INTO enrollments (student_id, course_id)
                     VALUES (?, ?)''', (data['student_id'], data['course_id']))
        db.commit()
        return jsonify({'message': 'Enrolled successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Already enrolled'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/students/<int:student_id>/courses', methods=['GET'])
@login_required
def student_courses(student_id):
    if session['user_id'] != student_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        courses = db.execute('''SELECT c.*, 
                               GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names
                               FROM courses c
                               JOIN enrollments e ON c.id = e.course_id
                               LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                               LEFT JOIN users u ON tc.teacher_id = u.id
                               WHERE e.student_id = ? AND c.status = 'active'
                               GROUP BY c.id
                               ORDER BY c.title''', (student_id,)).fetchall()
        return jsonify([dict(course) for course in courses])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/students/<int:student_id>/subject-combination', methods=['GET'])
@login_required
def get_student_subject_combination(student_id):
    """Get the subject combination for a student based on their level"""
    try:
        if session['user_id'] != student_id and session.get('role') != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        # Get student info
        student = db.execute('''SELECT level, department FROM users WHERE id = ?''',
                            (student_id,)).fetchone()
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        level = student['level']
        department = student['department']
        
        # Get compulsory courses for the student's level
        compulsory_courses = db.execute('''SELECT * FROM courses 
                                        WHERE level = ? AND is_compulsory = 1 AND status = 'active'
                                        ORDER BY title''', (level,)).fetchall()
        
        if level.startswith('MS'):
            # MS students see departmental courses for their level
            departmental_courses = db.execute('''SELECT * FROM courses 
                                               WHERE level = ? AND is_compulsory = 0 AND status = 'active'
                                               ORDER BY title''', (level,)).fetchall()
        elif level.startswith('HS') and department:
            # HS students see their department courses
            departmental_courses = db.execute('''SELECT * FROM courses 
                                               WHERE level = ? AND department = ? AND is_compulsory = 0 
                                               AND status = 'active'
                                               ORDER BY title''', 
                                            (level, department)).fetchall()
        else:
            departmental_courses = []
        
        # Get enrolled courses
        enrolled_courses = db.execute('''SELECT c.* FROM courses c
                                       JOIN enrollments e ON c.id = e.course_id
                                       WHERE e.student_id = ? AND c.status = 'active'
                                       ORDER BY c.is_compulsory DESC, c.title''', (student_id,)).fetchall()
        
        # Calculate total credits from enrolled courses
        total_credits = sum([course['credits'] for course in enrolled_courses])
        
        return jsonify({
            'student_info': {
                'level': level,
                'department': department
            },
            'compulsory_courses': [dict(course) for course in compulsory_courses],
            'departmental_courses': [dict(course) for course in departmental_courses],
            'enrolled_courses': [dict(course) for course in enrolled_courses],
            'total_credits': total_credits
        })
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Announcement routes
@app.route('/api/announcements', methods=['GET', 'POST'])
@login_required
def announcements():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            user_id = session['user_id']
            user_role = session.get('role')
            
            if user_role == 'student':
                query = '''SELECT a.*, u.first_name || " " || u.last_name as teacher_name, c.title as course_title
                          FROM announcements a
                          JOIN users u ON a.teacher_id = u.id
                          JOIN courses c ON a.course_id = c.id
                          JOIN enrollments e ON c.id = e.course_id
                          WHERE e.student_id = ? AND c.status = 'active' '''
                
                if course_id:
                    query += ' AND a.course_id = ?'
                    announcements = db.execute(query + ' ORDER BY a.created_at DESC', 
                                              (user_id, course_id)).fetchall()
                else:
                    announcements = db.execute(query + ' ORDER BY a.created_at DESC LIMIT 10', 
                                              (user_id,)).fetchall()
            else:
                query = '''SELECT a.*, u.first_name || " " || u.last_name as teacher_name, c.title as course_title
                          FROM announcements a
                          JOIN users u ON a.teacher_id = u.id
                          JOIN courses c ON a.course_id = c.id
                          WHERE c.status = 'active' '''
                
                if course_id:
                    query += ' AND a.course_id = ?'
                    announcements = db.execute(query + ' ORDER BY a.created_at DESC', 
                                              (course_id,)).fetchall()
                else:
                    announcements = db.execute(query + ' ORDER BY a.created_at DESC LIMIT 10').fetchall()
            
            return jsonify([dict(ann) for ann in announcements])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        if session.get('role') != 'teacher':
            return jsonify({'error': 'Only teachers can post announcements'}), 403
        
        try:
            data = request.json
            data['teacher_id'] = session['user_id']
            
            db.execute('''INSERT INTO announcements (course_id, teacher_id, title, content)
                         VALUES (?, ?, ?, ?)''',
                      (data['course_id'], data['teacher_id'], data['title'], data['content']))
            db.commit()
            
            # Create notifications for enrolled students
            students = db.execute('''SELECT student_id FROM enrollments WHERE course_id = ?''',
                                 (data['course_id'],)).fetchall()
            
            for student in students:
                db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                             VALUES (?, ?, ?, ?, ?)''',
                          (student['student_id'], 'New Announcement', 
                           f"New announcement posted: {data['title']}", 
                           'announcement', data['course_id']))
            db.commit()
            
            return jsonify({'message': 'Announcement created'}), 201
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

# Assignment routes
@app.route('/api/assignments', methods=['GET', 'POST'])
@login_required
def assignments():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            user_id = session['user_id']
            user_role = session.get('role')
            
            if user_role == 'student':
                query = '''SELECT a.*, u.first_name || " " || u.last_name as teacher_name
                          FROM assignments a
                          JOIN users u ON a.teacher_id = u.id
                          JOIN enrollments e ON a.course_id = e.course_id
                          WHERE e.student_id = ? '''
                
                if course_id:
                    query += ' AND a.course_id = ?'
                    assignments = db.execute(query + ' ORDER BY a.due_date', 
                                            (user_id, course_id)).fetchall()
                else:
                    assignments = db.execute(query + ' ORDER BY a.due_date', 
                                            (user_id,)).fetchall()
            else:
                if user_role == 'teacher':
                    query = '''SELECT a.*, u.first_name || " " || u.last_name as teacher_name
                              FROM assignments a
                              JOIN users u ON a.teacher_id = u.id
                              WHERE a.teacher_id = ? '''
                    
                    if course_id:
                        query += ' AND a.course_id = ?'
                        assignments = db.execute(query + ' ORDER BY a.due_date', 
                                                (user_id, course_id)).fetchall()
                    else:
                        assignments = db.execute(query + ' ORDER BY a.due_date', 
                                                (user_id,)).fetchall()
                else:
                    query = '''SELECT a.*, u.first_name || " " || u.last_name as teacher_name
                              FROM assignments a
                              JOIN users u ON a.teacher_id = u.id '''
                    
                    if course_id:
                        query += ' WHERE a.course_id = ?'
                        assignments = db.execute(query + ' ORDER BY a.due_date', 
                                                (course_id,)).fetchall()
                    else:
                        assignments = db.execute(query + ' ORDER BY a.due_date').fetchall()
            
            return jsonify([dict(asgn) for asgn in assignments])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        if session.get('role') != 'teacher':
            return jsonify({'error': 'Only teachers can create assignments'}), 403
        
        try:
            data = request.json
            data['teacher_id'] = session['user_id']
            
            db.execute('''INSERT INTO assignments (course_id, teacher_id, title, description, due_date, max_points)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (data['course_id'], data['teacher_id'], data['title'], 
                       data['description'], data['due_date'], data['max_points']))
            db.commit()
            
            # Create notifications for enrolled students
            students = db.execute('''SELECT student_id FROM enrollments WHERE course_id = ?''',
                                 (data['course_id'],)).fetchall()
            
            for student in students:
                db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                             VALUES (?, ?, ?, ?, ?)''',
                          (student['student_id'], 'New Assignment', 
                           f"New assignment posted: {data['title']}", 
                           'assignment', data['course_id']))
            db.commit()
            
            return jsonify({'message': 'Assignment created'}), 201
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/assignments/<int:assignment_id>', methods=['GET'])
@login_required
def get_assignment(assignment_id):
    try:
        db = get_db()
        assignment = db.execute('''SELECT a.*, u.first_name || " " || u.last_name as teacher_name
                                 FROM assignments a
                                 JOIN users u ON a.teacher_id = u.id
                                 WHERE a.id = ?''', (assignment_id,)).fetchone()
        
        if assignment:
            return jsonify(dict(assignment))
        return jsonify({'error': 'Assignment not found'}), 404
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Submission routes
@app.route('/api/submissions', methods=['POST'])
@login_required
def submit_assignment():
    if session.get('role') != 'student':
        return jsonify({'error': 'Only students can submit assignments'}), 403
    
    try:
        data = request.json
        data['student_id'] = session['user_id']
        
        db = get_db()
        
        # Check if assignment is past due
        assignment = db.execute('SELECT due_date FROM assignments WHERE id = ?', 
                               (data['assignment_id'],)).fetchone()
        if assignment:
            due_date = datetime.fromisoformat(assignment['due_date'].replace('Z', '+00:00'))
            if due_date < datetime.now():
                return jsonify({'error': 'Submission is closed. The due date has passed.'}), 400
        
        try:
            db.execute('''INSERT INTO submissions (assignment_id, student_id, content)
                         VALUES (?, ?, ?)''',
                      (data['assignment_id'], data['student_id'], data['content']))
            db.commit()
            return jsonify({'message': 'Submitted successfully'}), 201
        except sqlite3.IntegrityError:
            db.execute('''UPDATE submissions SET content = ?, submitted_at = CURRENT_TIMESTAMP
                         WHERE assignment_id = ? AND student_id = ?''',
                      (data['content'], data['assignment_id'], data['student_id']))
            db.commit()
            return jsonify({'message': 'Submission updated'}), 200
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/assignments/<int:assignment_id>/submissions', methods=['GET'])
@login_required
def get_submissions(assignment_id):
    try:
        db = get_db()
        user_id = session['user_id']
        user_role = session.get('role')
        
        if user_role == 'teacher':
            assignment = db.execute('SELECT teacher_id FROM assignments WHERE id = ?', 
                                   (assignment_id,)).fetchone()
            if not assignment or assignment['teacher_id'] != user_id:
                return jsonify({'error': 'Unauthorized to view these submissions'}), 403
        
        submissions = db.execute('''SELECT s.*, u.first_name || " " || u.last_name as student_name
                                   FROM submissions s
                                   JOIN users u ON s.student_id = u.id
                                   WHERE s.assignment_id = ?''', (assignment_id,)).fetchall()
        return jsonify([dict(sub) for sub in submissions])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Materials routes
@app.route('/api/materials', methods=['GET', 'POST'])
@login_required
def materials():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            user_id = session['user_id']
            user_role = session.get('role')
            
            if user_role == 'student':
                query = '''SELECT m.*, u.first_name || " " || u.last_name as teacher_name
                          FROM materials m
                          JOIN users u ON m.teacher_id = u.id
                          JOIN enrollments e ON m.course_id = e.course_id
                          WHERE e.student_id = ? AND m.course_id = ?'''
                
                materials = db.execute(query + ' ORDER BY m.created_at DESC', 
                                      (user_id, course_id)).fetchall()
            else:
                query = '''SELECT m.*, u.first_name || " " || u.last_name as teacher_name
                          FROM materials m
                          JOIN users u ON m.teacher_id = u.id
                          WHERE m.course_id = ?'''
                
                materials = db.execute(query + ' ORDER BY m.created_at DESC', 
                                      (course_id,)).fetchall()
            
            return jsonify([dict(mat) for mat in materials])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        if session.get('role') != 'teacher':
            return jsonify({'error': 'Only teachers can add materials'}), 403
        
        try:
            data = request.json
            data['teacher_id'] = session['user_id']
            
            db.execute('''INSERT INTO materials (course_id, teacher_id, title, description, file_url, material_type)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (data['course_id'], data['teacher_id'], data['title'], 
                       data['description'], data.get('file_url'), data['material_type']))
            db.commit()
            return jsonify({'message': 'Material added'}), 201
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

# Discussion routes
@app.route('/api/discussions', methods=['GET', 'POST'])
@login_required
def discussions():
    db = get_db()
    
    if request.method == 'GET':
        try:
            course_id = request.args.get('course_id')
            user_id = session['user_id']
            user_role = session.get('role')
            
            if user_role == 'student':
                enrollment = db.execute('''SELECT * FROM enrollments 
                                         WHERE student_id = ? AND course_id = ?''',
                                       (user_id, course_id)).fetchone()
                if not enrollment:
                    return jsonify({'error': 'Not enrolled in this course'}), 403
            
            posts = db.execute('''SELECT d.*, u.first_name || " " || u.last_name as author_name, u.role
                                 FROM discussion_posts d
                                 JOIN users u ON d.user_id = u.id
                                 WHERE d.course_id = ?
                                 ORDER BY d.created_at DESC''', (course_id,)).fetchall()
            return jsonify([dict(post) for post in posts])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            data['user_id'] = session['user_id']
            
            db.execute('''INSERT INTO discussion_posts (course_id, user_id, title, content)
                         VALUES (?, ?, ?, ?)''',
                      (data['course_id'], data['user_id'], data['title'], data['content']))
            db.commit()
            return jsonify({'message': 'Post created'}), 201
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/discussions/<int:post_id>/replies', methods=['GET', 'POST'])
@login_required
def discussion_replies(post_id):
    db = get_db()
    
    if request.method == 'GET':
        try:
            replies = db.execute('''SELECT r.*, u.first_name || " " || u.last_name as author_name, u.role
                                   FROM discussion_replies r
                                   JOIN users u ON r.user_id = u.id
                                   WHERE r.post_id = ?
                                   ORDER BY r.created_at''', (post_id,)).fetchall()
            return jsonify([dict(reply) for reply in replies])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            data['user_id'] = session['user_id']
            
            db.execute('''INSERT INTO discussion_replies (post_id, user_id, content)
                         VALUES (?, ?, ?)''',
                      (post_id, data['user_id'], data['content']))
            db.commit()
            return jsonify({'message': 'Reply added'}), 201
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

# Grading routes
@app.route('/api/grade', methods=['POST'])
@login_required
def grade_submission():
    if session.get('role') != 'teacher':
        return jsonify({'error': 'Only teachers can grade submissions'}), 403
    
    try:
        data = request.json
        db = get_db()
        
        assignment = db.execute('SELECT teacher_id, title, course_id FROM assignments WHERE id = ?', 
                               (data['assignment_id'],)).fetchone()
        if not assignment or assignment['teacher_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized to grade this assignment'}), 403
        
        db.execute('''UPDATE submissions SET grade = ?, feedback = ?
                     WHERE assignment_id = ? AND student_id = ?''',
                  (data['grade'], data.get('feedback'), 
                   data['assignment_id'], data['student_id']))
        db.commit()
        
        # Create notification for student
        db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                     VALUES (?, ?, ?, ?, ?)''',
                  (data['student_id'], 'Assignment Graded', 
                   f"Your assignment '{assignment['title']}' has been graded: {data['grade']} points", 
                   'grade', assignment['course_id']))
        db.commit()
        
        return jsonify({'message': 'Graded successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/students/<int:student_id>/grades', methods=['GET'])
@login_required
def student_grades(student_id):
    if session['user_id'] != student_id and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        course_id = request.args.get('course_id')
        
        query = '''SELECT s.*, a.title as assignment_title, a.max_points, c.title as course_title
                   FROM submissions s
                   JOIN assignments a ON s.assignment_id = a.id
                   JOIN courses c ON a.course_id = c.id
                   WHERE s.student_id = ? AND s.grade IS NOT NULL'''
        
        params = [student_id]
        
        if course_id:
            query += ' AND c.id = ?'
            params.append(course_id)
        
        query += ' ORDER BY s.submitted_at DESC'
        
        grades = db.execute(query, params).fetchall()
        return jsonify([dict(grade) for grade in grades])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Notification routes
@app.route('/api/notifications/<int:user_id>', methods=['GET'])
@login_required
def get_notifications(user_id):
    if session['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        notifications = db.execute('''SELECT * FROM notifications 
                                     WHERE user_id = ? 
                                     ORDER BY created_at DESC 
                                     LIMIT 50''', (user_id,)).fetchall()
        return jsonify([dict(notif) for notif in notifications])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        db = get_db()
        
        notification = db.execute('SELECT user_id FROM notifications WHERE id = ?', 
                                 (notification_id,)).fetchone()
        if not notification or notification['user_id'] != session['user_id']:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))
        db.commit()
        return jsonify({'message': 'Notification marked as read'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/notifications/<int:user_id>/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read(user_id):
    if session['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        db.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (user_id,))
        db.commit()
        return jsonify({'message': 'All notifications marked as read'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/notifications/<int:user_id>/clear-all', methods=['DELETE'])
@login_required
def clear_all_notifications(user_id):
    if session['user_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        db = get_db()
        db.execute('DELETE FROM notifications WHERE user_id = ?', (user_id,))
        db.commit()
        return jsonify({'message': 'All notifications cleared'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Course approval system routes
@app.route('/api/request-course-approval', methods=['POST'])
@login_required
def request_course_approval():
    try:
        data = request.json
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (data['teacher_id'],)).fetchone()
        
        if not user or user['role'] != 'teacher':
            return jsonify({'error': 'Only teachers can request course approvals'}), 403
        
        existing = db.execute('''SELECT * FROM teacher_courses 
                                WHERE teacher_id = ? AND course_id = ?''',
                             (data['teacher_id'], data['course_id'])).fetchone()
        if existing:
            return jsonify({'error': 'You are already teaching this course'}), 400
        
        pending_request = db.execute('''SELECT * FROM course_approval_requests 
                                       WHERE teacher_id = ? AND course_id = ? 
                                       AND status = "pending"''',
                                    (data['teacher_id'], data['course_id'])).fetchone()
        if pending_request:
            return jsonify({'error': 'You already have a pending request for this course'}), 400
        
        course = db.execute('SELECT * FROM courses WHERE id = ?',
                           (data['course_id'],)).fetchone()
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # Create approval request
        db.execute('''INSERT INTO course_approval_requests 
                    (teacher_id, course_id, status)
                    VALUES (?, ?, ?)''',
                  (data['teacher_id'], data['course_id'], 'pending'))
        
        # Create notification for all admins
        admins = db.execute('SELECT id FROM users WHERE role = "admin"').fetchall()
        for admin in admins:
            db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                         VALUES (?, ?, ?, ?, ?)''',
                      (admin['id'], 'Course Approval Request',
                       f"Teacher {user['first_name']} {user['last_name']} wants to teach {course['title']}",
                       'approval', data['course_id']))
        
        db.commit()
        
        return jsonify({
            'message': 'Course approval request submitted. An admin will review your request.',
            'requires_approval': True
        }), 200
        
    except sqlite3.IntegrityError as e:
        db.rollback()
        return jsonify({'error': 'Database error: ' + str(e)}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Server error: {str(e)}'}), 500
    
@app.route('/api/admin/pending-approvals', methods=['GET'])
@admin_required
def get_pending_approvals():
    try:
        db = get_db()
        
        pending_requests = db.execute('''SELECT 
            car.id as request_id,
            car.teacher_id,
            car.course_id,
            car.status,
            car.requested_at,
            u.first_name as teacher_first_name,
            u.last_name as teacher_last_name,
            u.email as teacher_email,
            u.teacher_code,
            c.title as course_title,
            c.course_code,
            c.description as course_description,
            c.credits,
            c.teacher_lock,
            CASE 
                WHEN EXISTS (SELECT 1 FROM teacher_courses tc WHERE tc.course_id = car.course_id) 
                THEN (SELECT u2.first_name || " " || u2.last_name 
                     FROM teacher_courses tc2 
                     JOIN users u2 ON tc2.teacher_id = u2.id 
                     WHERE tc2.course_id = car.course_id 
                     LIMIT 1)
                ELSE 'Not assigned'
            END as current_teacher
            FROM course_approval_requests car
            JOIN users u ON car.teacher_id = u.id
            JOIN courses c ON car.course_id = c.id
            WHERE car.status = 'pending'
            ORDER BY car.requested_at DESC''').fetchall()
        
        return jsonify([dict(request) for request in pending_requests])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
@app.route('/api/admin/approve-course-request/<int:request_id>', methods=['POST'])
@admin_required
def approve_course_request(request_id):
    try:
        data = request.json
        
        if 'action' not in data or data['action'] not in ['approve', 'reject']:
            return jsonify({'error': 'Invalid action. Use "approve" or "reject"'}), 400
        
        db = get_db()
        
        request_data = db.execute('''SELECT * FROM course_approval_requests 
                                   WHERE id = ?''', (request_id,)).fetchone()
        if not request_data:
            return jsonify({'error': 'Approval request not found'}), 404
        
        course = db.execute('SELECT * FROM courses WHERE id = ?',
                          (request_data['course_id'],)).fetchone()
        
        teacher = db.execute('SELECT * FROM users WHERE id = ?',
                           (request_data['teacher_id'],)).fetchone()
        
        if data['action'] == 'approve':
            if course['teacher_lock']:
                existing_teacher = db.execute('''SELECT tc.teacher_id, u.first_name, u.last_name 
                                               FROM teacher_courses tc
                                               JOIN users u ON tc.teacher_id = u.id
                                               WHERE tc.course_id = ?''', 
                                             (request_data['course_id'],)).fetchone()
                
                if existing_teacher:
                    if data.get('reassign', False):
                        db.execute('DELETE FROM teacher_courses WHERE course_id = ? AND teacher_id = ?',
                                  (request_data['course_id'], existing_teacher['teacher_id']))
                        
                        db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                                     VALUES (?, ?, ?, ?, ?)''',
                                  (existing_teacher['teacher_id'], 'Course Reassigned',
                                   f"You have been unassigned from {course['title']} to make room for another teacher",
                                   'course_update', request_data['course_id']))
                    else:
                        return jsonify({
                            'error': 'Course is already assigned to another teacher',
                            'current_teacher': {
                                'id': existing_teacher['teacher_id'],
                                'name': f"{existing_teacher['first_name']} {existing_teacher['last_name']}"
                            },
                            'course_title': course['title']
                        }), 400
            
            try:
                db.execute('''INSERT INTO teacher_courses (teacher_id, course_id)
                             VALUES (?, ?)''',
                          (request_data['teacher_id'], request_data['course_id']))
            except sqlite3.IntegrityError:
                pass
            
            db.execute('''UPDATE course_approval_requests 
                         SET status = 'approved', 
                             admin_id = ?,
                             admin_notes = ?,
                             reviewed_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                      (session['user_id'], data.get('notes', ''), request_id))
            
            db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                         VALUES (?, ?, ?, ?, ?)''',
                      (request_data['teacher_id'], 'Course Request Approved',
                       f"Your request to teach {course['title']} has been approved!",
                       'course_approval', request_data['course_id']))
            
            db.commit()
            return jsonify({'message': 'Course request approved successfully'}), 200
        
        elif data['action'] == 'reject':
            db.execute('''UPDATE course_approval_requests 
                         SET status = 'rejected', 
                             admin_id = ?,
                             admin_notes = ?,
                             reviewed_at = CURRENT_TIMESTAMP
                         WHERE id = ?''',
                      (session['user_id'], data.get('notes', ''), request_id))
            
            db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                         VALUES (?, ?, ?, ?, ?)''',
                      (request_data['teacher_id'], 'Course Request Rejected',
                       f"Your request to teach {course['title']} has been rejected. Reason: {data.get('notes', 'No reason provided')}",
                       'course_approval', request_data['course_id']))
            
            db.commit()
            return jsonify({'message': 'Course request rejected'}), 200
            
    except sqlite3.IntegrityError as e:
        db.rollback()
        return jsonify({'error': 'Database integrity error: ' + str(e)}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/approval-history', methods=['GET'])
@admin_required
def get_approval_history():
    try:
        db = get_db()
        
        all_requests = db.execute('''SELECT 
            car.*,
            u.first_name as teacher_first_name,
            u.last_name as teacher_last_name,
            c.title as course_title,
            c.course_code,
            admin.first_name || " " || admin.last_name as admin_name
            FROM course_approval_requests car
            JOIN users u ON car.teacher_id = u.id
            JOIN courses c ON car.course_id = c.id
            LEFT JOIN users admin ON car.admin_id = admin.id
            ORDER BY car.requested_at DESC
            LIMIT 50''').fetchall()
        
        return jsonify([dict(request) for request in all_requests])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin student management routes
@app.route('/api/admin/students', methods=['GET'])
@admin_required
def admin_get_students():
    try:
        db = get_db()
        search = request.args.get('search', '')
        
        query = '''SELECT id, first_name, last_name, email, student_id, 
                  phone, address, date_of_birth, gender,
                  department, level, status, created_at
                  FROM users WHERE role = "student" '''
        
        params = []
        if search:
            query += '''AND (first_name LIKE ? OR last_name LIKE ? OR 
                      email LIKE ? OR student_id LIKE ? OR department LIKE ? OR level LIKE ?) '''
            search_term = f'%{search}%'
            params.extend([search_term, search_term, search_term, search_term, search_term, search_term])
        
        query += 'ORDER BY level, last_name, first_name'
        
        students = db.execute(query, params).fetchall()
        return jsonify([dict(student) for student in students])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/students/<int:student_id>', methods=['PUT'])
@admin_required
def admin_update_student(student_id):
    try:
        data = request.json
        db = get_db()
        
        student = db.execute('SELECT * FROM users WHERE id = ? AND role = "student"', 
                            (student_id,)).fetchone()
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        if 'email' in data and data['email'] != student['email']:
            existing = db.execute('SELECT * FROM users WHERE email = ? AND id != ?',
                                (data['email'], student_id)).fetchone()
            if existing:
                return jsonify({'error': 'Email already exists'}), 400
        
        update_fields = []
        update_values = []
        
        fields_to_update = [
            'first_name', 'last_name', 'email', 'student_id',
            'phone', 'address', 'date_of_birth', 'gender',
            'department', 'level', 'status'
        ]
        
        for field in fields_to_update:
            if field in data:
                update_fields.append(f"{field} = ?")
                update_values.append(data[field])
        
        if 'password' in data and data['password']:
            hashed_password = generate_password_hash(data['password'])
            update_fields.append("password = ?")
            update_values.append(hashed_password)
        
        if update_fields:
            update_values.append(student_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            db.execute(query, update_values)
            db.commit()
        
        return jsonify({'message': 'Student updated successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/students/<int:student_id>/status', methods=['POST'])
@admin_required
def admin_toggle_student_status(student_id):
    try:
        data = request.json
        db = get_db()
        
        student = db.execute('SELECT * FROM users WHERE id = ?', 
                            (student_id,)).fetchone()
        if not student:
            return jsonify({'error': 'User not found'}), 404
        
        valid_statuses = ['active', 'suspended', 'graduated', 'inactive']
        if 'status' not in data or data['status'] not in valid_statuses:
            return jsonify({'error': 'Invalid status. Must be: ' + ', '.join(valid_statuses)}), 400
        
        db.execute('UPDATE users SET status = ? WHERE id = ?', 
                  (data['status'], student_id))
        db.commit()
        
        return jsonify({
            'message': f'User status updated to {data["status"]}',
            'status': data['status']
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/students/<int:student_id>', methods=['DELETE'])
@admin_required
def admin_delete_student(student_id):
    try:
        db = get_db()
        
        student = db.execute('SELECT * FROM users WHERE id = ? AND role = "student"', 
                            (student_id,)).fetchone()
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        enrollments = db.execute('SELECT COUNT(*) as count FROM enrollments WHERE student_id = ?',
                               (student_id,)).fetchone()['count']
        
        if enrollments > 0:
            return jsonify({
                'error': 'Cannot delete student with course enrollments',
                'enrollment_count': enrollments,
                'student_name': f"{student['first_name']} {student['last_name']}"
            }), 400
        
        try:
            db.execute('DELETE FROM submissions WHERE student_id = ?', (student_id,))
        except Exception as e:
            print(f"Note: Could not delete submissions for student {student_id}: {e}")
        
        try:
            db.execute('DELETE FROM notifications WHERE user_id = ?', (student_id,))
        except Exception as e:
            print(f"Note: Could not delete notifications for student {student_id}: {e}")
        
        db.execute('DELETE FROM users WHERE id = ?', (student_id,))
        db.commit()
        
        return jsonify({
            'message': 'Student deleted successfully',
            'student_name': f"{student['first_name']} {student['last_name']}"
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin teacher management routes
@app.route('/api/admin/teachers', methods=['GET', 'POST'])
@admin_required
def admin_teachers():
    db = get_db()
    
    if request.method == 'GET':
        try:
            teachers = db.execute('''SELECT u.*, 
                                    (SELECT COUNT(*) FROM teacher_courses WHERE teacher_id = u.id) as course_count
                                    FROM users u WHERE role = "teacher"
                                    ORDER BY last_name, first_name''').fetchall()
            return jsonify([dict(teacher) for teacher in teachers])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            required_fields = ['first_name', 'last_name', 'email', 'password', 'teacher_code']
            for field in required_fields:
                if field not in data or not data[field]:
                    return jsonify({'error': f'{field} is required'}), 400
            
            existing = db.execute('SELECT * FROM users WHERE teacher_code = ?', 
                                (data['teacher_code'],)).fetchone()
            if existing:
                return jsonify({'error': 'Teacher code already exists'}), 400
            
            existing_email = db.execute('SELECT * FROM users WHERE email = ?', 
                                      (data['email'],)).fetchone()
            if existing_email:
                return jsonify({'error': 'Email already exists'}), 400
            
            hashed_password = generate_password_hash(data['password'])
            
            cursor = db.execute('''INSERT INTO users (email, password, first_name, last_name, role, teacher_code, department)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (data['email'], hashed_password, data['first_name'], 
                           data['last_name'], 'teacher', data['teacher_code'], 
                           data.get('department', '')))
            
            teacher_id = cursor.lastrowid
            db.commit()
            
            return jsonify({
                'message': 'Teacher created successfully',
                'id': teacher_id
            }), 201
            
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        
@app.route('/api/admin/teachers/<int:teacher_id>', methods=['PUT'])
@admin_required
def admin_update_teacher(teacher_id):
    try:
        data = request.json
        db = get_db()
        
        teacher = db.execute('SELECT * FROM users WHERE id = ? AND role = "teacher"', 
                            (teacher_id,)).fetchone()
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        update_fields = []
        update_values = []
        
        fields_to_update = [
            'first_name', 'last_name', 'email', 'teacher_code',
            'phone', 'address', 'date_of_birth', 'gender',
            'department', 'specialization', 'status'
        ]
        
        for field in fields_to_update:
            if field in data:
                update_fields.append(f"{field} = ?")
                update_values.append(data[field])
        
        if 'password' in data and data['password']:
            hashed_password = generate_password_hash(data['password'])
            update_fields.append("password = ?")
            update_values.append(hashed_password)
        
        if update_fields:
            update_values.append(teacher_id)
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            db.execute(query, update_values)
            db.commit()
        
        return jsonify({'message': 'Teacher updated successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/teachers/<int:teacher_id>', methods=['DELETE'])
@admin_required
def admin_delete_teacher(teacher_id):
    try:
        db = get_db()
        
        teacher = db.execute('SELECT * FROM users WHERE id = ? AND role = "teacher"', 
                            (teacher_id,)).fetchone()
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        courses = db.execute('SELECT COUNT(*) as count FROM teacher_courses WHERE teacher_id = ?',
                            (teacher_id,)).fetchone()['count']
        
        if courses > 0:
            return jsonify({'error': 'Cannot delete teacher with assigned courses'}), 400
        
        db.execute('DELETE FROM users WHERE id = ?', (teacher_id,))
        db.commit()
        return jsonify({'message': 'Teacher deleted successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin course management routes
@app.route('/api/admin/courses', methods=['GET', 'POST'])
@admin_required
def admin_courses():
    db = get_db()
    
    if request.method == 'GET':
        try:
            courses = db.execute('''SELECT c.*, 
                                   u.first_name || " " || u.last_name as teacher_name
                                   FROM courses c
                                   LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                                   LEFT JOIN users u ON tc.teacher_id = u.id
                                   ORDER BY c.level, c.department, c.title''').fetchall()
            return jsonify([dict(course) for course in courses])
        except Exception as e:
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            db.execute('''INSERT INTO courses (title, description, course_code, credits, teacher_lock,
                         level, department, is_compulsory)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (data['title'], data['description'], data['course_code'], 
                       data['credits'], data.get('teacher_lock', 1),
                       data.get('level', 'all'), data.get('department', 'all'),
                       data.get('is_compulsory', 0)))
            db.commit()
            return jsonify({'message': 'Course created successfully'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Course code already exists'}), 400
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/courses/<int:course_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_course(course_id):
    db = get_db()
    
    if request.method == 'PUT':
        try:
            data = request.json
            db.execute('''UPDATE courses SET 
                         title = ?, description = ?, course_code = ?, 
                         credits = ?, teacher_lock = ?, status = ?,
                         level = ?, department = ?, is_compulsory = ?
                         WHERE id = ?''',
                      (data['title'], data['description'], data['course_code'],
                       data['credits'], data.get('teacher_lock', 1), 
                       data.get('status', 'active'), data.get('level', 'all'),
                       data.get('department', 'all'), data.get('is_compulsory', 0),
                       course_id))
            db.commit()
            return jsonify({'message': 'Course updated successfully'})
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Course code already exists'}), 400
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500
    
    elif request.method == 'DELETE':
        try:
            enrollments = db.execute('SELECT COUNT(*) as count FROM enrollments WHERE course_id = ?',
                                   (course_id,)).fetchone()['count']
            
            if enrollments > 0:
                db.execute('UPDATE courses SET status = "inactive" WHERE id = ?', (course_id,))
                db.commit()
                return jsonify({'message': 'Course deactivated (has enrollments)', 'deactivated': True})
            
            teacher_assignments = db.execute('SELECT COUNT(*) as count FROM teacher_courses WHERE course_id = ?',
                                           (course_id,)).fetchone()['count']
            
            if teacher_assignments > 0:
                db.execute('DELETE FROM teacher_courses WHERE course_id = ?', (course_id,))
            
            db.execute('DELETE FROM courses WHERE id = ?', (course_id,))
            db.commit()
            return jsonify({'message': 'Course deleted successfully'})
        except Exception as e:
            db.rollback()
            return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/enrollments/<int:course_id>/student/<int:student_id>', methods=['DELETE'])
@login_required
def remove_student_from_course(course_id, student_id):
    try:
        db = get_db()
        
        if session.get('role') == 'teacher':
            teacher_course = db.execute('''SELECT * FROM teacher_courses 
                                         WHERE teacher_id = ? AND course_id = ?''',
                                       (session['user_id'], course_id)).fetchone()
            if not teacher_course:
                return jsonify({'error': 'Unauthorized to remove students from this course'}), 403
        
        enrollment = db.execute('''SELECT * FROM enrollments 
                                 WHERE student_id = ? AND course_id = ?''',
                               (student_id, course_id)).fetchone()
        if not enrollment:
            return jsonify({'error': 'Student is not enrolled in this course'}), 404
        
        db.execute('DELETE FROM enrollments WHERE student_id = ? AND course_id = ?',
                  (student_id, course_id))
        db.commit()
        
        return jsonify({'message': 'Student removed from course successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin announcements routes
@app.route('/api/admin/announcements', methods=['POST'])
@admin_required
def admin_create_announcement():
    try:
        data = request.json
        db = get_db()
        
        admin = db.execute('SELECT * FROM users WHERE role = "admin"').fetchone()
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
        
        if data['target'] == 'teachers':
            users = db.execute('SELECT id FROM users WHERE role = "teacher"').fetchall()
        elif data['target'] == 'students':
            users = db.execute('SELECT id FROM users WHERE role = "student"').fetchall()
        else:
            return jsonify({'error': 'Invalid target'}), 400
        
        for user in users:
            db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                         VALUES (?, ?, ?, ?, ?)''',
                      (user['id'], data['title'], data['content'], 'announcement', 0))
        
        db.execute('''INSERT INTO admin_announcements (admin_id, title, content, target)
                     VALUES (?, ?, ?, ?)''',
                  (session['user_id'], data['title'], data['content'], data['target']))
        
        db.commit()
        
        return jsonify({'message': f'Announcement sent to {len(users)} {data["target"]}'}), 201
        
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/announcements/recent', methods=['GET'])
@admin_required
def get_recent_admin_announcements():
    try:
        db = get_db()
        
        announcements = db.execute('''SELECT aa.*, u.first_name || " " || u.last_name as admin_name
                                     FROM admin_announcements aa
                                     JOIN users u ON aa.admin_id = u.id
                                     ORDER BY aa.created_at DESC
                                     LIMIT 10''').fetchall()
        
        return jsonify([dict(ann) for ann in announcements])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/admin/backup', methods=['GET'])
@admin_required
def admin_backup():
    try:
        backup_file = f'lms_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        
        import shutil
        shutil.copy2(DATABASE, backup_file)
        
        return send_from_directory('.', backup_file, as_attachment=True)
    except Exception as e:
        return jsonify({'error': f'Backup failed: {str(e)}'}), 500

@app.route('/api/admin/reset', methods=['POST'])
@admin_required
def admin_reset():
    try:
        db = get_db()
        
        admin = db.execute('SELECT * FROM users WHERE role = "admin"').fetchone()
        
        tables = ['teacher_courses', 'enrollments', 'announcements', 'assignments', 
                  'submissions', 'materials', 'discussion_posts', 'discussion_replies', 
                  'notifications', 'courses', 'admin_announcements', 'course_approval_requests']
        
        for table in tables:
            db.execute(f'DROP TABLE IF EXISTS {table}')
        
        db.execute('DELETE FROM users WHERE role != "admin"')
        
        init_db()
        
        return jsonify({'message': 'System reset successfully'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Reset failed: {str(e)}'}), 500

# Health check route
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        db = get_db()
        db.execute('SELECT 1').fetchone()
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
        
# Get all enrollments for admin
@app.route('/api/admin/enrollments', methods=['GET'])
@admin_required
def admin_get_enrollments():
    try:
        db = get_db()
        
        enrollments = db.execute('''
            SELECT e.*, 
                   u.first_name, u.last_name, u.email, u.student_id, u.department, u.level,
                   c.title as course_title, c.course_code, c.credits,
                   t.first_name || " " || t.last_name as teacher_name
            FROM enrollments e
            JOIN users u ON e.student_id = u.id
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN teacher_courses tc ON c.id = tc.course_id
            LEFT JOIN users t ON tc.teacher_id = t.id
            WHERE u.role = 'student' AND c.status = 'active'
            ORDER BY u.level, u.department, e.enrolled_at DESC
        ''').fetchall()
        
        return jsonify([dict(enrollment) for enrollment in enrollments])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin remove student from course
@app.route('/api/admin/enrollments/<int:enrollment_id>', methods=['DELETE'])
@admin_required
def admin_remove_enrollment(enrollment_id):
    try:
        db = get_db()
        
        enrollment = db.execute('''
            SELECT e.*, u.first_name, u.last_name, u.email, c.title as course_title
            FROM enrollments e
            JOIN users u ON e.student_id = u.id
            JOIN courses c ON e.course_id = c.id
            WHERE e.id = ?
        ''', (enrollment_id,)).fetchone()
        
        if not enrollment:
            return jsonify({'error': 'Enrollment not found'}), 404
        
        db.execute('DELETE FROM enrollments WHERE id = ?', (enrollment_id,))
        
        db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                     VALUES (?, ?, ?, ?, ?)''',
                  (enrollment['student_id'], 'Course Enrollment Removed',
                   f"You have been removed from {enrollment['course_title']} by administrator",
                   'enrollment', enrollment['course_id']))
        
        db.commit()
        
        return jsonify({
            'message': 'Student removed from course successfully',
            'student_name': f"{enrollment['first_name']} {enrollment['last_name']}",
            'course_title': enrollment['course_title']
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Search enrollments
@app.route('/api/admin/enrollments/search', methods=['GET'])
@admin_required
def search_enrollments():
    try:
        search_term = request.args.get('q', '').strip()
        if not search_term:
            return jsonify([])
        
        db = get_db()
        search_pattern = f'%{search_term}%'
        
        enrollments = db.execute('''
            SELECT e.*, 
                   u.first_name, u.last_name, u.email, u.student_id, u.department, u.level,
                   c.title as course_title, c.course_code, c.credits,
                   t.first_name || " " || t.last_name as teacher_name
            FROM enrollments e
            JOIN users u ON e.student_id = u.id
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN teacher_courses tc ON c.id = tc.course_id
            LEFT JOIN users t ON tc.teacher_id = t.id
            WHERE u.role = 'student' 
            AND c.status = 'active'
            AND (u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ? 
                 OR u.student_id LIKE ? OR c.title LIKE ? OR c.course_code LIKE ?
                 OR u.level LIKE ? OR u.department LIKE ?)
            ORDER BY e.enrolled_at DESC
        ''', (search_pattern, search_pattern, search_pattern, 
              search_pattern, search_pattern, search_pattern,
              search_pattern, search_pattern)).fetchall()
        
        return jsonify([dict(enrollment) for enrollment in enrollments])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get enrollments by student ID
@app.route('/api/admin/students/<int:student_id>/enrollments', methods=['GET'])
@admin_required
def get_student_enrollments(student_id):
    try:
        db = get_db()
        
        enrollments = db.execute('''
            SELECT e.*, c.title, c.course_code, c.credits,
                   t.first_name || " " || t.last_name as teacher_name
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            LEFT JOIN teacher_courses tc ON c.id = tc.course_id
            LEFT JOIN users t ON tc.teacher_id = t.id
            WHERE e.student_id = ? AND c.status = 'active'
            ORDER BY c.title
        ''', (student_id,)).fetchall()
        
        return jsonify([dict(enrollment) for enrollment in enrollments])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin update teacher status endpoint
@app.route('/api/admin/teachers/<int:teacher_id>/status', methods=['POST'])
@admin_required
def admin_update_teacher_status(teacher_id):
    try:
        data = request.json
        db = get_db()
        
        teacher = db.execute('SELECT * FROM users WHERE id = ? AND role = "teacher"', 
                            (teacher_id,)).fetchone()
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        valid_statuses = ['active', 'suspended', 'terminated', 'inactive']
        if 'status' not in data or data['status'] not in valid_statuses:
            return jsonify({'error': 'Invalid status. Must be: ' + ', '.join(valid_statuses)}), 400
        
        admin = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        db.execute('UPDATE users SET status = ? WHERE id = ?', 
                  (data['status'], teacher_id))
        
        status_action = "suspended" if data['status'] == 'suspended' else "terminated" if data['status'] == 'terminated' else "reactivated"
        
        db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                     VALUES (?, ?, ?, ?, ?)''',
                  (teacher_id, f'Account {status_action.capitalize()}',
                   f"Your account has been {status_action} by administrator {admin['first_name']} {admin['last_name']}.",
                   'account_status', 0))
        
        if data['status'] == 'terminated':
            teacher_courses = db.execute('''SELECT c.title FROM courses c
                                          JOIN teacher_courses tc ON c.id = tc.course_id
                                          WHERE tc.teacher_id = ?''', (teacher_id,)).fetchall()
            
            db.execute('DELETE FROM teacher_courses WHERE teacher_id = ?', (teacher_id,))
            
            if teacher_courses:
                courses_list = ", ".join([course['title'] for course in teacher_courses])
                db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                             VALUES (?, ?, ?, ?, ?)''',
                          (session['user_id'], 'Teacher Termination Completed',
                           f"Teacher {teacher['first_name']} {teacher['last_name']} has been removed from courses: {courses_list}",
                           'teacher_termination', teacher_id))
            
            for course in teacher_courses:
                students = db.execute('''SELECT DISTINCT e.student_id FROM enrollments e
                                       WHERE e.course_id IN 
                                       (SELECT course_id FROM teacher_courses WHERE teacher_id = ?)''',
                                    (teacher_id,)).fetchall()
                
                for student in students:
                    db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                                 VALUES (?, ?, ?, ?, ?)''',
                              (student['student_id'], 'Course Teacher Change',
                               f"Teacher for {course['title']} has been changed. Please check course details.",
                               'course_update', 0))
        
        db.commit()
        
        return jsonify({
            'message': f'Teacher account {status_action} successfully',
            'status': data['status'],
            'teacher_name': f"{teacher['first_name']} {teacher['last_name']}"
        })
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get teacher details for admin
@app.route('/api/admin/teachers/<int:teacher_id>/details', methods=['GET'])
@admin_required
def get_teacher_details(teacher_id):
    try:
        db = get_db()
        
        teacher = db.execute('''SELECT * FROM users WHERE id = ? AND role = "teacher"''',
                            (teacher_id,)).fetchone()
        
        if not teacher:
            return jsonify({'error': 'Teacher not found'}), 404
        
        courses = db.execute('''SELECT c.* FROM courses c
                               JOIN teacher_courses tc ON c.id = tc.course_id
                               WHERE tc.teacher_id = ?
                               ORDER BY c.title''', (teacher_id,)).fetchall()
        
        announcements = db.execute('''SELECT a.*, c.title as course_title 
                                    FROM announcements a
                                    JOIN courses c ON a.course_id = c.id
                                    WHERE a.teacher_id = ?
                                    ORDER BY a.created_at DESC
                                    LIMIT 5''', (teacher_id,)).fetchall()
        
        assignments = db.execute('''SELECT a.*, c.title as course_title 
                                  FROM assignments a
                                  JOIN courses c ON a.course_id = c.id
                                  WHERE a.teacher_id = ?
                                  ORDER BY a.created_at DESC
                                  LIMIT 5''', (teacher_id,)).fetchall()
        
        return jsonify({
            'teacher': dict(teacher),
            'courses': [dict(course) for course in courses],
            'announcements': [dict(announcement) for announcement in announcements],
            'assignments': [dict(assignment) for assignment in assignments]
        })
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get all levels
@app.route('/api/levels', methods=['GET'])
@login_required
def get_levels():
    try:
        db = get_db()
        
        user_levels = db.execute('''SELECT DISTINCT level FROM users 
                                   WHERE level IS NOT NULL AND level != '' 
                                   ORDER BY level''').fetchall()
        
        course_levels = db.execute('''SELECT DISTINCT level FROM courses 
                                     WHERE level IS NOT NULL AND level != '' AND level != 'all'
                                     ORDER BY level''').fetchall()
        
        all_levels = set()
        for level in user_levels:
            if level['level']:
                all_levels.add(level['level'])
        for level in course_levels:
            if level['level']:
                all_levels.add(level['level'])
        
        sorted_levels = sorted(all_levels, key=lambda x: (x[0], int(x[2]) if len(x) > 2 else 0))
        
        return jsonify(sorted_levels)
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get all departments
@app.route('/api/departments', methods=['GET'])
@login_required
def get_departments():
    try:
        db = get_db()
        
        user_departments = db.execute('''SELECT DISTINCT department FROM users 
                                        WHERE department IS NOT NULL AND department != '' 
                                        ORDER BY department''').fetchall()
        
        course_departments = db.execute('''SELECT DISTINCT department FROM courses 
                                          WHERE department IS NOT NULL AND department != '' AND department != 'all'
                                          ORDER BY department''').fetchall()
        
        all_departments = set()
        for dept in user_departments:
            if dept['department']:
                all_departments.add(dept['department'])
        for dept in course_departments:
            if dept['department']:
                all_departments.add(dept['department'])
        
        return jsonify(sorted(all_departments))
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Teacher removing student from course
@app.route('/api/teachers/<int:teacher_id>/courses/<int:course_id>/students/<int:student_id>', methods=['DELETE'])
@teacher_required
def teacher_remove_student(teacher_id, course_id, student_id):
    try:
        if session['user_id'] != teacher_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db = get_db()
        
        teacher_course = db.execute('''SELECT * FROM teacher_courses 
                                     WHERE teacher_id = ? AND course_id = ?''',
                                   (teacher_id, course_id)).fetchone()
        if not teacher_course:
            return jsonify({'error': 'You are not teaching this course'}), 403
        
        enrollment = db.execute('''SELECT e.*, u.first_name, u.last_name, c.title as course_title
                                 FROM enrollments e
                                 JOIN users u ON e.student_id = u.id
                                 JOIN courses c ON e.course_id = c.id
                                 WHERE e.student_id = ? AND e.course_id = ?''',
                              (student_id, course_id)).fetchone()
        if not enrollment:
            return jsonify({'error': 'Student is not enrolled in this course'}), 404
        
        db.execute('DELETE FROM enrollments WHERE student_id = ? AND course_id = ?',
                  (student_id, course_id))
        
        db.execute('''INSERT INTO notifications (user_id, title, message, type, reference_id)
                     VALUES (?, ?, ?, ?, ?)''',
                  (student_id, 'Removed from Course',
                   f"You have been removed from {enrollment['course_title']} by your teacher",
                   'enrollment', course_id))
        
        db.commit()
        
        return jsonify({
            'message': 'Student removed from course successfully',
            'student_name': f"{enrollment['first_name']} {enrollment['last_name']}",
            'course_title': enrollment['course_title']
        })
        
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Admin deploy courses by department
@app.route('/api/admin/departments/deploy-courses', methods=['POST'])
@admin_required
def deploy_department_courses():
    try:
        data = request.json
        db = get_db()
        
        required_fields = ['department', 'courses', 'level']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        department = data['department']
        courses_data = data['courses']
        level = data['level']
        
        valid_departments = ['Science', 'Arts', 'Commercial']
        valid_levels = ['MS1', 'MS2', 'MS3', 'HS1', 'HS2', 'HS3']
        
        if department not in valid_departments:
            return jsonify({'error': f'Invalid department. Must be one of: {", ".join(valid_departments)}'}), 400
        
        if level not in valid_levels:
            return jsonify({'error': f'Invalid level. Must be one of: {", ".join(valid_levels)}'}), 400
        
        deployed_courses = []
        
        for course_info in courses_data:
            existing = db.execute('''SELECT * FROM courses 
                                   WHERE course_code = ? AND department = ? AND level = ?''',
                                (course_info['code'], department, level)).fetchone()
            
            if existing:
                db.execute('''UPDATE courses 
                           SET title = ?, description = ?, credits = ?, teacher_lock = ?
                           WHERE id = ?''',
                          (course_info['title'], course_info['description'], 
                           course_info.get('credits', 3), course_info.get('teacher_lock', 1),
                           existing['id']))
                deployed_courses.append({
                    'course_code': course_info['code'],
                    'action': 'updated',
                    'id': existing['id']
                })
            else:
                cursor = db.execute('''INSERT INTO courses 
                              (title, description, course_code, credits, teacher_lock, 
                               department, level, is_compulsory)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                           (course_info['title'], course_info['description'], 
                            course_info['code'], course_info.get('credits', 3),
                            course_info.get('teacher_lock', 1), department, level, 
                            0))  # Department courses are NOT compulsory
                deployed_courses.append({
                    'course_code': course_info['code'],
                    'action': 'created',
                    'id': cursor.lastrowid
                })
        
        db.commit()
        
        # Auto-enroll students in their department courses
        if level.startswith('HS'):
            # For HS students, auto-enroll in their department courses
            students = db.execute('''SELECT id FROM users 
                                   WHERE role = "student" AND department = ? AND level = ?''',
                                (department, level)).fetchall()
            
            for student in students:
                student_id = student['id']
                for course_info in deployed_courses:
                    if course_info['action'] == 'created':
                        try:
                            db.execute('''INSERT INTO enrollments (student_id, course_id)
                                         VALUES (?, ?)''',
                                      (student_id, course_info['id']))
                        except sqlite3.IntegrityError:
                            pass
        else:
            # For MS students, don't auto-enroll - let them choose
            pass
        
        db.commit()
        
        return jsonify({
            'message': f'Successfully deployed {len(deployed_courses)} courses for {department} department ({level})',
            'deployed_courses': deployed_courses,
            'auto_enrolled_students': len(students) if level.startswith('HS') else 0
        }), 201
        
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get department courses for admin
@app.route('/api/admin/departments/courses', methods=['GET'])
@admin_required
def get_department_courses():
    try:
        department = request.args.get('department')
        level = request.args.get('level')
        
        db = get_db()
        
        query = '''SELECT c.*, 
                  GROUP_CONCAT(u.first_name || " " || u.last_name) as teacher_names,
                  COUNT(DISTINCT e.student_id) as enrolled_students
                  FROM courses c
                  LEFT JOIN teacher_courses tc ON c.id = tc.course_id
                  LEFT JOIN users u ON tc.teacher_id = u.id
                  LEFT JOIN enrollments e ON c.id = e.course_id
                  WHERE c.department != 'all' '''
        
        params = []
        
        if department:
            query += ' AND c.department = ?'
            params.append(department)
        
        if level:
            query += ' AND c.level = ?'
            params.append(level)
        
        query += ' GROUP BY c.id ORDER BY c.level, c.title'
        
        courses = db.execute(query, params).fetchall()
        return jsonify([dict(course) for course in courses])
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get all teachers by department
@app.route('/api/admin/teachers/by-department', methods=['GET'])
@admin_required
def get_teachers_by_department():
    try:
        department = request.args.get('department', '')
        
        db = get_db()
        
        query = '''SELECT u.*, 
                  (SELECT COUNT(*) FROM teacher_courses WHERE teacher_id = u.id) as course_count
                  FROM users u 
                  WHERE u.role = "teacher" '''
        
        params = []
        if department:
            query += ' AND u.department = ?'
            params.append(department)
        
        query += ' ORDER BY u.last_name, u.first_name'
        
        teachers = db.execute(query, params).fetchall()
        return jsonify([dict(teacher) for teacher in teachers])
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    
@app.route('/api/admin/clear-all-courses', methods=['DELETE'])
@admin_required
def admin_clear_all_courses():
    """Delete all non-compulsory courses from the system"""
    try:
        db = get_db()
        
        # Get counts before deletion
        total_courses = db.execute('SELECT COUNT(*) as count FROM courses').fetchone()['count']
        compulsory_courses = db.execute('SELECT COUNT(*) as count FROM courses WHERE is_compulsory = 1').fetchone()['count']
        elective_courses = total_courses - compulsory_courses
        
        enrollment_count = db.execute('SELECT COUNT(*) as count FROM enrollments').fetchone()['count']
        teacher_assignment_count = db.execute('SELECT COUNT(*) as count FROM teacher_courses').fetchone()['count']
        
        # Delete elective courses and their related data
        # Get elective course IDs first
        elective_course_ids = db.execute('SELECT id FROM courses WHERE is_compulsory = 0').fetchall()
        elective_ids = [course['id'] for course in elective_course_ids]
        
        if elective_ids:
            # Delete related data for elective courses
            placeholders = ','.join(['?'] * len(elective_ids))
            
            # Delete from various tables
            db.execute(f'DELETE FROM enrollments WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM teacher_courses WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM course_approval_requests WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM announcements WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM assignments WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM materials WHERE course_id IN ({placeholders})', elective_ids)
            db.execute(f'DELETE FROM discussion_posts WHERE course_id IN ({placeholders})', elective_ids)
            
            # Finally delete the elective courses
            db.execute(f'DELETE FROM courses WHERE id IN ({placeholders})', elective_ids)
        
        db.commit()
        
        return jsonify({
            'message': f'Cleared {elective_courses} elective courses successfully. {compulsory_courses} compulsory courses retained.',
            'cleared': {
                'elective_courses': elective_courses,
                'enrollments': enrollment_count,
                'teacher_assignments': teacher_assignment_count,
                'compulsory_courses_retained': compulsory_courses
            }
        })
        
    except Exception as e:
        db.rollback()
        print(f"Error clearing elective courses: {e}")
        return jsonify({'error': f'Failed to clear courses: {str(e)}'}), 500
    
# Get compulsory courses for a level
@app.route('/api/admin/compulsory-courses/<level>', methods=['GET'])
@admin_required
def get_compulsory_courses_by_level(level):
    """Get all compulsory courses for a specific level"""
    try:
        db = get_db()
        
        courses = db.execute('''SELECT * FROM courses 
                              WHERE level = ? AND is_compulsory = 1 AND status = 'active'
                              ORDER BY title''', (level,)).fetchall()
        
        return jsonify([dict(course) for course in courses])
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Add/Update compulsory course
@app.route('/api/admin/compulsory-courses', methods=['POST', 'PUT'])
@admin_required
def manage_compulsory_courses():
    """Add or update a compulsory course"""
    try:
        data = request.json
        db = get_db()
        
        if request.method == 'POST':
            # Check if course code already exists
            existing = db.execute('SELECT * FROM courses WHERE course_code = ?', 
                                (data['course_code'],)).fetchone()
            if existing:
                return jsonify({'error': 'Course code already exists'}), 400
            
            # Insert new compulsory course
            cursor = db.execute('''INSERT INTO courses (title, description, course_code, credits, 
                                 teacher_lock, level, department, is_compulsory, status)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                              (data['title'], data.get('description', ''), data['course_code'], 
                               data['credits'], 1, data['level'], 'all', 1, 'active'))
            
            course_id = cursor.lastrowid
            db.commit()
            
            # Auto-enroll all students in this level
            students = db.execute('''SELECT id FROM users 
                                   WHERE role = "student" AND level = ? AND status = "active"''',
                                (data['level'],)).fetchall()
            
            for student in students:
                try:
                    db.execute('''INSERT INTO enrollments (student_id, course_id)
                                 VALUES (?, ?)''', (student['id'], course_id))
                except sqlite3.IntegrityError:
                    pass  # Already enrolled
            
            db.commit()
            
            return jsonify({
                'message': 'Compulsory course created and students auto-enrolled',
                'course_id': course_id,
                'auto_enrolled_count': len(students)
            }), 201
            
        elif request.method == 'PUT':
            # Update compulsory course
            if 'id' not in data:
                return jsonify({'error': 'Course ID required for update'}), 400
            
            db.execute('''UPDATE courses SET 
                         title = ?, description = ?, course_code = ?, 
                         credits = ?, level = ?
                         WHERE id = ? AND is_compulsory = 1''',
                      (data['title'], data.get('description', ''), data['course_code'],
                       data['credits'], data['level'], data['id']))
            
            db.commit()
            
            return jsonify({'message': 'Compulsory course updated successfully'})
            
    except sqlite3.IntegrityError as e:
        db.rollback()
        if 'course_code' in str(e):
            return jsonify({'error': 'Course code already exists'}), 400
        return jsonify({'error': 'Database integrity error'}), 400
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Delete compulsory course
@app.route('/api/admin/compulsory-courses/<int:course_id>', methods=['DELETE'])
@admin_required
def delete_compulsory_course(course_id):
    """Delete a compulsory course"""
    try:
        db = get_db()
        
        # Check if course exists and is compulsory
        course = db.execute('SELECT * FROM courses WHERE id = ? AND is_compulsory = 1', 
                          (course_id,)).fetchone()
        if not course:
            return jsonify({'error': 'Compulsory course not found'}), 404
        
        # Check if course has enrollments
        enrollment_count = db.execute('SELECT COUNT(*) as count FROM enrollments WHERE course_id = ?',
                                    (course_id,)).fetchone()['count']
        
        if enrollment_count > 0:
            # Instead of deleting, deactivate the course
            db.execute('UPDATE courses SET status = "inactive" WHERE id = ?', (course_id,))
            db.commit()
            return jsonify({
                'message': 'Compulsory course deactivated (has enrollments)',
                'deactivated': True,
                'course_title': course['title']
            })
        
        # Delete the course
        db.execute('DELETE FROM courses WHERE id = ?', (course_id,))
        db.commit()
        
        return jsonify({
            'message': 'Compulsory course deleted successfully',
            'course_title': course['title']
        })
        
    except Exception as e:
        db.rollback()
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# Get all compulsory courses grouped by level
@app.route('/api/admin/compulsory-courses', methods=['GET'])
@admin_required
def get_all_compulsory_courses():
    """Get all compulsory courses grouped by level"""
    try:
        db = get_db()
        
        courses = db.execute('''SELECT * FROM courses 
                              WHERE is_compulsory = 1 AND status = 'active'
                              ORDER BY level, title''').fetchall()
        
        # Group by level
        courses_by_level = {}
        for course in courses:
            level = course['level']
            if level not in courses_by_level:
                courses_by_level[level] = []
            courses_by_level[level].append(dict(course))
        
        return jsonify(courses_by_level)
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

if __name__ == '__main__':
    lock_files = ['lms_database.db-journal', 'lms_database.db-wal', 'lms_database.db-shm']
    for lock_file in lock_files:
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
                print(f"🗑️  Removed lock file: {lock_file}")
            except:
                pass
    
    init_db()
    print("\n" + "="*60)
    print("🎓 SCHOOL LEARNING MANAGEMENT SYSTEM")
    print("="*60)
    print("\n📌 Open your browser and go to:")
    print("   ➡️  http://localhost:5000")
    print("\n🔐 Login Credentials:")
    print("   👑 Admin:      admin@school.edu / admin123")
    print("   👨‍🏫 Teacher:   teacher@school.edu / teacher123 / TCH001")
    print("   👨‍🎓 Students:  Register on the portal")
    print("\n📚 Level System:")
    print("   🏫 Middle School: MS1, MS2, MS3")
    print("   🎓 High School:   HS1, HS2, HS3 (Department required)")
    print("\n📖 Compulsory Courses:")
    print("   1. Mathematics")
    print("   2. English Language")
    print("   3. Data Processing")
    print("\n🔧 Health Check:")
    print("   🌐 http://localhost:5000/api/health")
    print("\n" + "="*60 + "\n")
    app.run(debug=True, port=5000, host='0.0.0.0', threaded=True)