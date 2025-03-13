import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session as flask_session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_login import login_required
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# 初始化Flask应用
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_audit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 设置最大内容长度为16MB
app.jinja_env.autoescape = True  # 确保自动转义
app.jinja_env.trim_blocks = False  # 不要修剪块
app.jinja_env.lstrip_blocks = False  # 不要去除左侧空白

# 初始化数据库
db = SQLAlchemy(app)

# 定义数据模型
class ScanSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_id = db.Column(db.String(50), nullable=False)
    hostname = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    employee_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    scan_time = db.Column(db.DateTime, nullable=False)
    scan_start_time = db.Column(db.DateTime, nullable=True)
    scan_end_time = db.Column(db.DateTime, nullable=True)
    scan_duration = db.Column(db.Float, nullable=True)  # 存储扫描耗时（秒）
    
    def __repr__(self):
        return f'<ScanSession {self.id}>'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('scan_session.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    extension = db.Column(db.String(20), nullable=False)
    creation_time = db.Column(db.DateTime, nullable=False)
    modified_time = db.Column(db.DateTime, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    owner = db.Column(db.String(100), nullable=False)
    
    # 新增字段
    author = db.Column(db.String(255), nullable=True)
    last_saved_by = db.Column(db.String(255), nullable=True)
    revision = db.Column(db.String(50), nullable=True)
    company = db.Column(db.String(255), nullable=True)
    manager = db.Column(db.String(255), nullable=True)
    
    # 确保关系定义正确
    session = db.relationship('ScanSession', backref=db.backref('documents', lazy=True))
    
    def __repr__(self):
        return f'<Document {self.id}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('scan_session.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(1000), nullable=False)
    keyword = db.Column(db.String(100), nullable=False)
    detection_time = db.Column(db.DateTime, nullable=False)
    
    session = db.relationship('ScanSession', backref=db.backref('alerts', lazy=True))
    
    def __repr__(self):
        return f'<Alert {self.id}>'

# 创建数据库表
with app.app_context():
    db.create_all()

# API路由
@app.route('/api/ping', methods=['GET'])
def ping():
    """用于测试服务器连接的简单接口"""
    return jsonify({"status": "success", "message": "服务器连接正常"}), 200

@app.route('/api/submit', methods=['POST'])
def submit_data():
    """接收客户端提交的数据"""
    try:
        data = request.json
        
        # 创建扫描会话
        scan_time = datetime.strptime(data['scan_time'], '%Y-%m-%d %H:%M:%S')
        
        # 处理可选的扫描时间字段
        scan_start_time = None
        scan_end_time = None
        scan_duration = None
        
        if 'scan_start_time' in data and data['scan_start_time']:
            scan_start_time = datetime.strptime(data['scan_start_time'], '%Y-%m-%d %H:%M:%S')
        
        if 'scan_end_time' in data and data['scan_end_time']:
            scan_end_time = datetime.strptime(data['scan_end_time'], '%Y-%m-%d %H:%M:%S')
        
        if 'scan_duration' in data:
            scan_duration = data['scan_duration']
        
        session = ScanSession(
            machine_id=data['machine_id'],
            hostname=data['hostname'],
            ip_address=data['ip_address'],
            employee_name=data['employee_name'],
            department=data['department'],
            scan_time=scan_time,
            scan_start_time=scan_start_time,
            scan_end_time=scan_end_time,
            scan_duration=scan_duration
        )
        db.session.add(session)
        db.session.commit()
        
        # 添加文档记录
        for doc_data in data['documents']:
            creation_time = datetime.strptime(doc_data['creation_time'], '%Y-%m-%d %H:%M:%S')
            modified_time = datetime.strptime(doc_data['modified_time'], '%Y-%m-%d %H:%M:%S')
            
            document = Document(
                session_id=session.id,
                file_name=doc_data['file_name'],
                file_path=doc_data['file_path'],
                extension=doc_data['extension'],
                creation_time=creation_time,
                modified_time=modified_time,
                size=doc_data['size'],
                owner=doc_data['owner'],
                # 新增字段
                author=doc_data.get('author'),
                last_saved_by=doc_data.get('last_saved_by'),
                revision=doc_data.get('revision'),
                company=doc_data.get('company'),
                manager=doc_data.get('manager')
            )
            db.session.add(document)
        
        # 添加告警记录
        # 使用扫描时间作为检测时间（如果未提供）
        detection_time = scan_time
        if 'detection_time' in data and data['detection_time']:
            try:
                detection_time = datetime.strptime(data['detection_time'], '%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        for alert_data in data['alerts']:
            # 处理关键词字段，可能是字符串或列表
            keyword = alert_data.get('keyword', '')
            if not keyword and 'matched_keywords' in alert_data:
                if isinstance(alert_data['matched_keywords'], list):
                    keyword = ','.join(alert_data['matched_keywords'])
                else:
                    keyword = str(alert_data['matched_keywords'])
            
            alert = Alert(
                session_id=session.id,
                file_name=alert_data['file_name'],
                file_path=alert_data['file_path'],
                keyword=keyword,
                detection_time=detection_time
            )
            db.session.add(alert)
        
        db.session.commit()
        
        return jsonify({"status": "success", "message": "数据已成功保存"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

# Web界面路由
@app.route('/')
def index():
    """主页"""
    # 获取统计数据
    session_count = ScanSession.query.count()
    document_count = Document.query.count()
    alert_count = Alert.query.count()
    department_count = db.session.query(ScanSession.department).distinct().count()
    
    # 获取最近的扫描会话
    recent_sessions = ScanSession.query.order_by(desc(ScanSession.scan_time)).limit(5).all()
    
    # 获取最近的告警信息
    recent_alerts = Alert.query.join(ScanSession).order_by(desc(Alert.detection_time)).limit(5).all()
    
    # 获取部门统计数据 - 修复文档数量和告警数量相同的问题
    departments = db.session.query(
        ScanSession.department,
        db.func.count(db.distinct(Document.id)).label('doc_count'),
        db.func.count(db.distinct(Alert.id)).label('alert_count')
    ).outerjoin(Document, Document.session_id == ScanSession.id)\
     .outerjoin(Alert, Alert.session_id == ScanSession.id)\
     .group_by(ScanSession.department).all()
    
    # 确保有数据
    if departments:
        department_labels = [str(d[0]) for d in departments]
        department_docs = [int(d[1]) for d in departments]
        department_alerts = [int(d[2]) for d in departments]
    else:
        department_labels = []
        department_docs = []
        department_alerts = []
    
    # 添加调试信息
    print(f"首页部门数据: {departments}")
    print(f"部门标签: {department_labels}")
    print(f"部门文档数: {department_docs}")
    print(f"部门告警数: {department_alerts}")
    
    # 测试数据，如果没有真实数据则使用这些
    if not departments:
        department_labels = ["市场部", "销售部", "技术部"]
        department_docs = [150, 200, 100]
        department_alerts = [10, 25, 5]
        print("使用测试数据")
    
    # 使用json.dumps确保数据格式正确，不使用ensure_ascii参数，这样不会转义中文
    department_labels_json = json.dumps(department_labels, ensure_ascii=False)
    department_docs_json = json.dumps(department_docs)
    department_alerts_json = json.dumps(department_alerts)
    
    print(f"JSON格式数据:")
    print(f"标签: {department_labels_json}")
    print(f"文档: {department_docs_json}")
    print(f"告警: {department_alerts_json}")
    
    return render_template(
        'index.html',
        session_count=session_count,
        document_count=document_count,
        alert_count=alert_count,
        department_count=department_count,
        recent_sessions=recent_sessions,
        recent_alerts=recent_alerts,
        department_labels=department_labels_json,
        department_docs=department_docs_json,
        department_alerts=department_alerts_json
    )

@app.route('/sessions')
def sessions():
    """扫描会话列表"""
    all_sessions = ScanSession.query.order_by(desc(ScanSession.scan_time)).all()
    return render_template('sessions.html', sessions=all_sessions)

@app.route('/session/<int:session_id>')
def session_detail(session_id):
    """会话详情"""
    session = ScanSession.query.get_or_404(session_id)
    
    # 获取文档列表
    documents = Document.query.filter_by(session_id=session_id).all()
    
    # 获取告警列表
    alerts = Alert.query.filter_by(session_id=session_id).all()
    
    # 统计文件类型
    extensions = {}
    for doc in documents:
        ext = doc.extension if doc.extension else "未知"
        if ext in extensions:
            extensions[ext] += 1
        else:
            extensions[ext] = 1
    
    # 统计关键词 - 分词统计
    keywords = {}
    for alert in alerts:
        # 将关键词按逗号分隔并统计
        if alert.keyword:
            for kw in alert.keyword.split(','):
                kw = kw.strip()
                if kw:
                    if kw in keywords:
                        keywords[kw] += 1
                    else:
                        keywords[kw] = 1
    
    # 对关键词统计结果按出现频率排序
    sorted_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)
    keywords = dict(sorted_keywords)
    
    # 为图表准备格式化的数据
    extensions_labels = list(extensions.keys())
    extensions_data = list(extensions.values())
    
    keywords_labels = list(keywords.keys())
    keywords_data = list(keywords.values())
    
    return render_template(
        'session_detail.html',
        session=session,
        documents=documents,
        alerts=alerts,
        extensions=extensions,
        keywords=keywords,
        # 添加格式化的数据用于图表
        extensions_labels=json.dumps(extensions_labels),
        extensions_data=json.dumps(extensions_data),
        keywords_labels=json.dumps(keywords_labels),
        keywords_data=json.dumps(keywords_data)
    )

@app.route('/documents')
def all_documents():
    """所有文档列表"""
    # 使用原始 SQL 查询加载文档和关联的会话信息
    documents = Document.query.order_by(desc(Document.modified_time)).all()
    
    # 手动加载每个文档的会话信息
    for doc in documents:
        doc.session = ScanSession.query.get(doc.session_id)
    
    return render_template('documents.html', documents=documents)

@app.route('/alerts')
def all_alerts():
    """所有告警列表"""
    alerts = Alert.query.join(ScanSession).order_by(desc(Alert.detection_time)).all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/statistics')
def statistics():
    try:
        # 修改检查登录方式，暂时去除登录验证
        # if not session.get('user_id'):
        #     return redirect(url_for('login'))
            
        # 从数据库获取统计数据
        has_data = False
        
        # 获取总扫描次数、文档数和告警数
        session_count = ScanSession.query.count()
        document_count = Document.query.count()
        alert_count = Alert.query.count()
        
        print(f"统计页面数据: 扫描次数={session_count}, 文档数={document_count}, 告警数={alert_count}")
        
        # 只有当有实际数据时才设置has_data
        has_data = (session_count > 0 and document_count > 0)
        
        # 设置默认空数据
        departments = []
        extensions = []
        keywords = []
        top_employees = []
        top_keywords = []
        
        # 测试数据 - 用于调试
        test_data = [
            ["市场部", 5, 94, 12], 
            ["销售部", 3, 76, 8],
            ["技术部", 7, 120, 21],
            ["人力资源", 2, 45, 5],
            ["财务部", 4, 68, 15]
        ]
        test_data_json = json.dumps(test_data)
        
        # 其他测试数据
        test_extensions = [
            [".pdf", 57],
            [".docx", 45],
            [".xlsx", 32],
            [".pptx", 28],
            [".txt", 15]
        ]
        test_extensions_json = json.dumps(test_extensions)
        
        test_keywords = [
            ["合同", 23],
            ["财务", 18],
            ["机密", 15],
            ["保密", 12],
            ["内部", 10]
        ]
        test_keywords_json = json.dumps(test_keywords)
        
        test_employees = [
            ["张三", 12],
            ["李四", 10],
            ["王五", 8],
            ["赵六", 7],
            ["钱七", 6]
        ]
        test_employees_json = json.dumps(test_employees)
        
        test_top_keywords = test_keywords
        test_top_keywords_json = test_keywords_json
        
        # 只有当有数据时才查询详细统计信息
        if has_data:
            print("正在获取部门统计数据...")
            
            # 按部门统计 - 使用SQLAlchemy
            departments = db.session.query(
                ScanSession.department,
                db.func.count(db.distinct(ScanSession.id)).label('session_count'),
                db.func.count(db.distinct(Document.id)).label('document_count'),
                db.func.count(db.distinct(Alert.id)).label('alert_count')
            ).outerjoin(Document, Document.session_id == ScanSession.id)\
             .outerjoin(Alert, Alert.session_id == ScanSession.id)\
             .group_by(ScanSession.department).all()
            
            print(f"部门统计数据: {departments}")
            
            # 新增：部门扫描人数统计 - 每部门有多少不同的人进行了扫描
            dept_personnel = db.session.query(
                ScanSession.department,
                db.func.count(db.distinct(ScanSession.employee_name)).label('personnel_count')
            ).group_by(ScanSession.department)\
             .order_by(db.desc('personnel_count'))\
             .all()
            
            print(f"部门扫描人数统计: {dept_personnel}")
            
            # 新增：部门扫描会话数统计 - 每部门有多少扫描会话
            dept_sessions = db.session.query(
                ScanSession.department,
                db.func.count(ScanSession.id).label('session_count')
            ).group_by(ScanSession.department)\
             .order_by(db.desc('session_count'))\
             .all()
            
            print(f"部门扫描会话数统计: {dept_sessions}")
            
            # 按文件类型统计
            extensions = db.session.query(
                Document.extension,
                db.func.count(Document.id).label('count')
            ).group_by(Document.extension)\
             .order_by(db.desc('count'))\
             .limit(10).all()
            
            print(f"文件类型统计数据: {extensions}")
            
            # 按关键词统计 - 处理逗号分隔关键词
            keywords = []
            raw_keywords = db.session.query(Alert.keyword, Alert.id).all()
            keyword_count = {}
            
            for kw_pair in raw_keywords:
                if kw_pair[0]:  # 确保关键词不为空
                    for kw in kw_pair[0].split(','):
                        kw = kw.strip()
                        if kw:
                            if kw in keyword_count:
                                keyword_count[kw] += 1
                            else:
                                keyword_count[kw] = 1
            
            # 转换为列表格式并排序
            for kw, count in sorted(keyword_count.items(), key=lambda x: x[1], reverse=True):
                keywords.append([kw, count])
            
            # 限制关键词数量为前10个
            keywords = keywords[:10]
            
            print(f"关键词统计数据: {keywords}")
            
            # 员工告警TOP10
            top_employees = db.session.query(
                ScanSession.employee_name,
                db.func.count(Alert.id).label('alert_count')
            ).join(Alert, Alert.session_id == ScanSession.id)\
             .group_by(ScanSession.employee_name)\
             .order_by(db.desc('alert_count'))\
             .limit(10).all()
            
            # 关键词告警TOP10
            top_keywords = keywords[:10]
        
        # 准备JSON数据 - 确保所有数据为正确格式
        # 转换为JSON前先处理为简单结构
        departments_json = json.dumps([[str(d[0]) if d[0] is not None else "未知", 
                                      int(d[1]) if d[1] is not None else 0, 
                                      int(d[2]) if d[2] is not None else 0, 
                                      int(d[3]) if d[3] is not None else 0] for d in departments]) if departments else "[]"
                                      
        extensions_json = json.dumps([[str(e[0]) if e[0] is not None else "未知", 
                                     int(e[1]) if e[1] is not None else 0] for e in extensions]) if extensions else "[]"
                                     
        keywords_json = json.dumps(keywords) if keywords else "[]"
        
        top_employees_json = json.dumps([[str(e[0]) if e[0] is not None else "未知", 
                                        int(e[1]) if e[1] is not None else 0] for e in top_employees]) if top_employees else "[]"
                                        
        top_keywords_json = json.dumps(top_keywords) if top_keywords else "[]"
        
        # 新增：部门告警数据和部门人员数据
        dept_alerts_json = json.dumps([[str(d[0]) if d[0] is not None else "未知", 
                                      int(d[1]) if d[1] is not None else 0] for d in dept_alerts], ensure_ascii=False) if 'dept_alerts' in locals() and dept_alerts else "[]"
                                      
        dept_personnel_json = json.dumps([[str(d[0]) if d[0] is not None else "未知", 
                                         int(d[1]) if d[1] is not None else 0] for d in dept_personnel], ensure_ascii=False) if 'dept_personnel' in locals() and dept_personnel else "[]"
        
        # 新增：部门扫描会话数据
        dept_sessions_json = json.dumps([[str(d[0]) if d[0] is not None else "未知", 
                                        int(d[1]) if d[1] is not None else 0] for d in dept_sessions], ensure_ascii=False) if 'dept_sessions' in locals() and dept_sessions else "[]"
        
        print(f"准备JSON数据: departments_json={departments_json[:100]}...")
        
        return render_template('statistics.html', 
                              has_data=has_data,
                              session_count=session_count,
                              document_count=document_count,
                              alert_count=alert_count,
                              departments=departments_json,
                              extensions=extensions_json,
                              keywords=keywords_json,
                              top_employees=top_employees_json,
                              top_keywords=top_keywords_json,
                              # 新增数据
                              dept_alerts=dept_alerts_json,
                              dept_personnel=dept_personnel_json,
                              dept_sessions=dept_sessions_json,
                              # 测试数据
                              test_data_json=test_data_json,
                              test_extensions_json=test_extensions_json,
                              test_keywords_json=test_keywords_json,
                              test_employees_json=test_employees_json)
    except Exception as e:
        print(f"统计页面错误: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # 创建测试数据
        test_data = [
            ["市场部", 5, 94, 12], 
            ["销售部", 3, 76, 8],
            ["技术部", 7, 120, 21],
            ["人力资源", 2, 45, 5],
            ["财务部", 4, 68, 15]
        ]
        test_data_json = json.dumps(test_data)
        
        # 其他测试数据
        test_extensions = [
            [".pdf", 57],
            [".docx", 45],
            [".xlsx", 32],
            [".pptx", 28],
            [".txt", 15]
        ]
        test_extensions_json = json.dumps(test_extensions)
        
        test_keywords = [
            ["合同", 23],
            ["财务", 18],
            ["机密", 15],
            ["保密", 12],
            ["内部", 10]
        ]
        test_keywords_json = json.dumps(test_keywords)
        
        test_employees = [
            ["张三", 12],
            ["李四", 10],
            ["王五", 8],
            ["赵六", 7],
            ["钱七", 6]
        ]
        test_employees_json = json.dumps(test_employees)
        
        return render_template('statistics.html', 
                              has_data=False,
                              error=str(e),
                              session_count=0,
                              document_count=0,
                              alert_count=0,
                              departments="[]",
                              extensions="[]",
                              keywords="[]",
                              top_employees="[]",
                              top_keywords="[]",
                              # 新增数据
                              dept_alerts="[]",
                              dept_personnel="[]",
                              dept_sessions="[]",
                              # 测试数据
                              test_data_json=test_data_json,
                              test_extensions_json=test_extensions_json,
                              test_keywords_json=test_keywords_json,
                              test_employees_json=test_employees_json)

@app.context_processor
def utility_processor():
    def get_session(session_id):
        return ScanSession.query.get(session_id)
    return dict(get_session=get_session)

@app.route('/admin/import', methods=['GET', 'POST'])
# 先注释掉login_required，直到完成用户登录系统的设置
# @login_required  # 确保只有管理员可以访问
def import_scan_data():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('未选择文件')
            return redirect(request.url)
        
        file = request.files['file']
        password = request.form.get('password')
        
        if file.filename == '':
            flash('未选择文件')
            return redirect(request.url)
        
        if file and file.filename.endswith('.sdat') and password:
            try:
                # 读取文件内容
                file_data = file.read()
                
                # 前16字节是salt
                salt = file_data[:16]
                encrypted_data = file_data[16:]
                
                # 生成解密密钥
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                cipher = Fernet(key)
                
                # 解密数据
                try:
                    decrypted_data = cipher.decrypt(encrypted_data)
                    scan_data = json.loads(decrypted_data)
                    
                    # 处理扫描数据
                    session_id = process_scan_data(scan_data)
                    
                    flash('扫描数据导入成功')
                    return redirect(url_for('session_detail', session_id=session_id))
                except Exception as e:
                    flash(f'解密失败，密码可能不正确: {str(e)}')
                    return redirect(request.url)
            except Exception as e:
                flash(f'导入失败: {str(e)}')
                return redirect(request.url)
    
    # GET请求显示导入表单
    return render_template('admin/import.html')

def process_scan_data(scan_data):
    """处理导入的扫描数据"""
    # 验证数据格式
    required_fields = ['machine_id', 'hostname', 'ip_address', 
                      'employee_name', 'department', 'scan_time', 
                      'documents', 'alerts']
    
    for field in required_fields:
        if field not in scan_data:
            raise ValueError(f"缺少必要字段: {field}")
    
    # 创建扫描会话
    scan_time = datetime.strptime(scan_data['scan_time'], '%Y-%m-%d %H:%M:%S')
    
    # 处理可选的扫描时间字段
    scan_start_time = None
    scan_end_time = None
    scan_duration = None
    
    if 'scan_start_time' in scan_data and scan_data['scan_start_time']:
        scan_start_time = datetime.strptime(scan_data['scan_start_time'], '%Y-%m-%d %H:%M:%S')
    
    if 'scan_end_time' in scan_data and scan_data['scan_end_time']:
        scan_end_time = datetime.strptime(scan_data['scan_end_time'], '%Y-%m-%d %H:%M:%S')
    
    if 'scan_duration' in scan_data:
        scan_duration = scan_data['scan_duration']
    
    session = ScanSession(
        machine_id=scan_data['machine_id'],
        hostname=scan_data['hostname'],
        ip_address=scan_data['ip_address'],
        employee_name=scan_data['employee_name'],
        department=scan_data['department'],
        scan_time=scan_time,
        scan_start_time=scan_start_time,
        scan_end_time=scan_end_time,
        scan_duration=scan_duration
    )
    db.session.add(session)
    db.session.commit()
    
    # 添加文档记录
    for doc_data in scan_data['documents']:
        creation_time = datetime.strptime(doc_data['creation_time'], '%Y-%m-%d %H:%M:%S')
        modified_time = datetime.strptime(doc_data['modified_time'], '%Y-%m-%d %H:%M:%S')
        
        document = Document(
            session_id=session.id,
            file_name=doc_data['file_name'],
            file_path=doc_data['file_path'],
            extension=doc_data['extension'],
            creation_time=creation_time,
            modified_time=modified_time,
            size=doc_data['size'],
            owner=doc_data['owner'],
            # 新增字段
            author=doc_data.get('author'),
            last_saved_by=doc_data.get('last_saved_by'),
            revision=doc_data.get('revision'),
            company=doc_data.get('company'),
            manager=doc_data.get('manager')
        )
        db.session.add(document)
    
    # 添加告警记录
    # 从主数据对象中获取detection_time，如果不存在则使用scan_time
    detection_time = scan_time
    if 'detection_time' in scan_data and scan_data['detection_time']:
        try:
            detection_time = datetime.strptime(scan_data['detection_time'], '%Y-%m-%d %H:%M:%S')
        except:
            pass
    
    for alert_data in scan_data['alerts']:
        # 处理关键词字段，可能是字符串或列表
        keyword = alert_data.get('keyword', '')
        if not keyword and 'matched_keywords' in alert_data:
            if isinstance(alert_data['matched_keywords'], list):
                keyword = ','.join(alert_data['matched_keywords'])
            else:
                keyword = str(alert_data['matched_keywords'])
        
        alert = Alert(
            session_id=session.id,
            file_name=alert_data['file_name'],
            file_path=alert_data['file_path'],
            keyword=keyword,
            detection_time=detection_time
        )
        db.session.add(alert)
    
    db.session.commit()
    return session.id

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')