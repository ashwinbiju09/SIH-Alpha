from application import UPLOAD_FOLDER, app, db, bcrypt
from flask import render_template, redirect, url_for, request, flash
from application.models import User, Form_1, Form_2, Form_3, Form_4,Form_5
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = "E:/SIH v2/application/media/user_documents/"


def createFolder(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER + request.form['name'])

def createFolder(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER + request.form['name'])
    
#Home route
@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')


#Register route
@app.route("/register", methods=['POST','GET'])
def register():
    if request.method == 'POST' :

        #Data from form stored in Database
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        role = request.form['role']

        if role == 'Proponent':
            createFolder(UPLOAD_FOLDER)

        state = request.form['state']
        city = request.form['city']
        org_name = request.form['org_name']
        aadhar = request.form['aadhar']

        #Hasing Password
        hashed_pwd = bcrypt.generate_password_hash(password).decode('utf-8')

        #Storing in DB
        user = User(name=name, email=email, password=hashed_pwd, phone=phone, role=role, state=state, city=city, org_name=org_name,aadhar=aadhar)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html')


#Login route
@app.route("/login",methods=['POST','GET'])
def login():

    if request.method == 'POST' :
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password=password):
            if user.role == "Proponent":
                login_user(user)
                return redirect(url_for('proponent'))
            elif user.role == "Tech" and user.permission == True:
                login_user(user)
                return redirect(url_for('committee'))
            elif user.role == "Admin":
                login_user(user)
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('login'))

    return render_template('login.html')


#Logout route
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


#User routes based on role
@app.route("/proponent")
@login_required
def proponent():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    return render_template('/proponent/profile.html')


@app.route("/committee")
@login_required
def committee():
    if not current_user.role == "Tech":
        return redirect(url_for('error'))
    return render_template('/committee/profile.html')

@app.route("/admin")
@login_required
def admin():
    if not current_user.role == "Admin":
        return redirect(url_for('error'))
    return render_template('/admin/profile.html')

#Error routes
@app.route("/error")
def error():
    return render_template('/errors/403.html')


#Proponent routes
@app.route("/application",methods=['POST','GET'])
@login_required
def application():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        return redirect(url_for('form_1'))
    return render_template('/proponent/terms.html')


@app.route("/existing_applications",methods=['POST','GET'])
@login_required
def existing_applications():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == "POST":
        return redirect(url_for('dpr/<int:id>'))
    allq = Form_2.query.all()
    print(allq)
    return render_template('/proponent/existing_applications.html',allq=allq)

@app.route("/status")
@login_required
def status(id):
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    p = Form_1.query.filter_by(id=id).first()
    return render_template('/proponent/status.html',p=p)


@app.route("/notifications")
@login_required
def notifications():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    return render_template('/proponent/notifications.html')

@app.route("/dpr/<int:id>",methods=['POST','GET'])
@login_required
def dpr(id):
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))

    p = Form_1.query.filter_by(id=id).first()
    q = Form_2.query.filter_by(id=id).first()
    r = Form_3.query.filter_by(id=id).first()
    s = Form_4.query.filter_by(id=id).first()
    t = Form_5.query.filter_by(id=id).first()

    return render_template('/proponent/dpr.html' , p=p, q=q, r=r, s=s, t=t)


#Form routes
@app.route("/form_1",methods=['POST','GET'])
@login_required
def form_1():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        name = request.form['name']
        email = request.form['email']
        add1 = request.form['add1']
        add2 = request.form['add2']
        phone = request.form['phone']
        state = request.form['state']
        pincode = request.form['pincode']

        #DB commits
        form_1 = Form_1(name=name, email=email, add1=add1, add2=add2, phone=phone, state=state, pincode=pincode)
        db.session.add(form_1)
        db.session.commit()
        return redirect(url_for('form_2'))
    f1 = Form_1.query.all()
    print(f1)
    return render_template('/proponent/form_1.html',f1=f1)


@app.route("/form_2",methods=['POST','GET'])
@login_required
def form_2():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        name = request.form['name']
        add1 = request.form['add1']
        add2 = request.form['add2']
        mot = request.form['mot']
        mot_name = request.form['mot_name']
        mot_add1 = request.form['mot_add1']
        mot_add2 = request.form['mot_add2']
        distance = request.form['distance']
        area = request.form['area']
        cop = request.form['cop']

        type = request.form['type']
        if(type == "Others"):
          other_type = request.form['other_type']
        else:
          other_type = "none"

        ownership = request.form['ownership']
        availability = request.form['availability']
        utilities = ', '.join(request.form.getlist('utilities'))

        category = request.form['category']
        if(type == "Others"):
          other_cat = request.form['other_cat']
        else:
          other_cat = "none"

        ancillary = request.form['ancillary']
        cost = request.form['cost']
        share = request.form['share']

        #Snippet to input file and store in local directory
        file = request.files['land_proof']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - land_proof.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['land_certificate']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - land_certificate.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['boq']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - boq.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['difference']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - difference.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['milestones']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - milestones.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        #DB commits
        form_2 = Form_2(name=name, add1=add1, add2=add2, mot=mot, mot_name=mot_name, mot_add1=mot_add1, mot_add2=mot_add2, distance=distance, area=area, cop=cop, type=type, other_type=other_type, ownership=ownership, availability=availability, utilities=utilities, category=category, other_cat=other_cat, ancillary=ancillary, cost=cost, share=share)
        db.session.add(form_2)
        db.session.commit()
        return redirect(url_for('form_3'))
    f2 = Form_2.query.all()
    print(f2)
    return render_template('/proponent/form_2.html',f2=f2)

@app.route("/form_3",methods=['POST','GET'])
@login_required
def form_3():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        inc = request.form['inc']
        asi =  ', '.join(request.form.getlist('asi'))
        noc = request.form['noc']
        nop = request.form['nop']
        ub = request.form['ub']


        #Snippet to input file and store in local directory
        file = request.files['scope']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - scope.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['schematic_plan']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - schematic_plan.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['proposed_method']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - proposed_method.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['fastrack']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - fastrack.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['utilization_plan']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - utilization_plan.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['economic_impact']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - economic_impact.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['integration']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - integration.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        #DB commits
        form_3 = Form_3(inc=inc, asi=asi, noc=noc, nop=nop, ub=ub)
        db.session.add(form_3)
        db.session.commit()
        return redirect(url_for('form_4'))
    f3 = Form_3.query.all()
    print(f3)
    return render_template('/proponent/form_3.html',f3=f3)

@app.route("/form_4",methods=['POST','GET'])
@login_required
def form_4():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        nd = request.form['nd']
        demand = request.form['demand']
        pg = request.form['pg']
        apo = request.form['apo']

        #Snippet to input file and store in local directory
        file = request.files['need']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - need.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['excellence']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - excellence.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['estimation']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - estimation.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['benefits']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - benefits.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['equity']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - equity.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        #DB commits
        form_4 = Form_4(nd=nd, demand=demand, pg=pg, apo=apo)
        db.session.add(form_4)
        db.session.commit()
        return redirect(url_for('form_5'))
    f4 = Form_4.query.all()
    print(f4)
    return render_template('/proponent/form_4.html',f4=f4)

@app.route("/form_5",methods=['POST','GET'])
@login_required
def form_5():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        prev = request.form['prev']
        od = request.form['od']
        comp = request.form['comp']

        #Snippet to input file and store in local directory
        file = request.files['maintanence']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - maintanence.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['design']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - design.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['u-certificate']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - u-certificate.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['details']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - details.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))

        file = request.files['proof']
        if file.filename == '':
            flash('No selected file')
        filename = current_user.name + " - proof.pdf"
        file.save(os.path.join('E:/SIH v2/application/media/user_documents/' + current_user.name, filename))



        #DB commits
        form_5 = Form_5(prev=prev, od=od, comp=comp)
        db.session.add(form_5)
        db.session.commit()
        return redirect(url_for('existing_applications'))
    f5 = Form_5.query.all()
    print(f5)
    return render_template('/proponent/form_5.html',f5=f5)

@app.route('/delete/<int:id>')
def delete(id):
    p = Form_1.query.filter_by(id=id).first()
    q = Form_2.query.filter_by(id=id).first()
    r = Form_3.query.filter_by(id=id).first()
    s = Form_4.query.filter_by(id=id).first()
    t = Form_5.query.filter_by(id=id).first()
    db.session.delete(p)
    db.session.delete(q)
    db.session.delete(r)
    db.session.delete(s)
    db.session.delete(t)
    db.session.commit()
    return redirect("/")


#tech_committee routes
@app.route("/projects",methods=['POST','GET'])
@login_required
def projects():
    if not current_user.role == "Tech":
         return redirect(url_for('error'))
    
    p = Form_2.query.all()

    # if request.method == "POST":
    #     req = request.form['method']
    #     if req == "1" :
    #         return redirect(url_for('cdpr'))
    #     if req == "2":
    #         return redirect(url_for('sanctioned_projects'))
    #     if req == "3":
    #         return redirect(url_for('rejected_projects'))
    return render_template('/committee/projects.html', p=p)


@app.route("/cdpr/<int:id>",methods=['POST','GET'])
@login_required
def cdpr(id):
        if not current_user.role == "Tech":
            return redirect(url_for('error'))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()

        return render_template("/committee/dpr.html",p=p,q=q,r=r,s=s,t=t)
        

@app.route("/cdpr_marks/<int:id>",methods=['POST','GET'])
@login_required
def cdpr_marks(id):
        if not current_user.role == "Tech":
            return redirect(url_for('error'))
            
        if request.method == 'POST':
            p = Form_1.query.filter_by(id=id).first()
            q = Form_2.query.filter_by(id=id).first()
            r = Form_3.query.filter_by(id=id).first()
            s = Form_4.query.filter_by(id=id).first()
            if request.form['qm1']:
                q.m1 = request.form['qm1']
            if request.form['qm2']:
                q.m2 = request.form['qm2']
            if request.form['qm4']:
                q.m4 = request.form['qm4']
            if request.form['qm5']:
                q.m5 = request.form['qm5']
            if request.form['qm6']:
                q.m6 = request.form['qm6']
            if request.form['qm8']:
                q.m8 = request.form['qm8']

            if request.form['rm3']:
                r.m3 = request.form['rm3']
            if request.form['rm7']:
                r.m7 = request.form['rm7']
            if request.form['rm8']:
                r.m8 = request.form['rm8']
            if request.form['rm9']:
                r.m9 = request.form['rm9']
            if request.form['rm10']:
                r.m10 = request.form['rm10']

            if request.form['sm2']:
                s.m2 = request.form['sm2']
            if request.form['sm3']:
                s.m3 = request.form['sm3']
            if request.form['sm4']:
                s.m4 = request.form['sm4']
            if request.form['sm6']:
                s.m6 = request.form['sm6']

            db.session.add(q)
            db.session.add(r)
            db.session.add(s)
            db.session.commit()

            t = Form_5.query.filter_by(id=id).first()
            return redirect(url_for('cdpr',id=id))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()
        return render_template('committee/dpr_marks.html',p=p,q=q,r=r,s=s,t=t)

@app.route('/filter_projects/<string:state>', methods=['GET','POST'])
def fil_pro(state):
    p = Form_2.query.filter_by(add2=state).all()
    return render_template('/committee/filter_projects.html',p=p)

@app.route("/sanctioned_projects",methods=['POST','GET'])
@login_required
def sanctioned_projects():
        if not current_user.role == "Tech":
            return redirect(url_for('error'))

        return render_template("/committee/sanctioned.html")

@app.route("/rejected_projects",methods=['POST','GET'])
@login_required
def rejected_projects():
        if not current_user.role == "Tech":
            return redirect(url_for('error'))

        return render_template("/committee/rejected.html")


#admin routes
@app.route("/approval",methods=['POST','GET'])
@login_required
def approval():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))

    users = User.query.filter_by(role='Tech').all()

    if request.method == "POST":
            permission = request.form['permission']
            id = request.form['user_id']
            user = User.query.get(id)
            if user :
                value = permission == '1' if True else False
                setattr(user,'permission',value)
            db.session.commit()
            return redirect(url_for('approval'))

    return render_template('admin/permission.html',users=users)

@app.route("/project",methods=['POST','GET'])
@login_required
def project():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    
    p = Form_2.query.all()

    # if request.method == "POST":
    #     req = request.form['method']
    #     if req == "1" :
    #         return redirect(url_for('cdpr'))
    #     if req == "2":
    #         return redirect(url_for('sanctioned_projects'))
    #     if req == "3":
    #         return redirect(url_for('rejected_projects'))
    return render_template('/admin/projects.html', p=p)

@app.route("/dpr_admin/<int:id>",methods=['POST','GET'])
@login_required
def dpr_admin(id):
        if not current_user.role == "Admin":
            return redirect(url_for('error'))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()

        return render_template("/admin/dpr.html",p=p,q=q,r=r,s=s,t=t)

