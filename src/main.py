"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User

#from models import Person

#///////////////////////////////////
#OJO AQUÍ SE IMPORTA EL Flask_JWT
#///////////////////////////////////

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
#AL IMPORTAR INCORPORAMOS LOS SUPERPODERES QUE ESTA TECNOLOGIA flask_jwt_extended TIENE PARA OFRECER
#OJO COMO CADA LINEA IMPORTADA VIENE DEL MISMO SITIO flask_jwt_extended LO PUEDO IMPORTAR EN UNA MISMA LINEA
#ASÍ from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager



app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

#///////////////////////////////////
#OJO AQUÍ SE CONFIGURA EL Flask_JWT
#///////////////////////////////////
# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "palabra-secreta-para-configuracion"  # Change this!
jwt = JWTManager(app)

#///////////////////////////////////
#EXPLICACIÓN DE LA CONFIGURACIÓN
# recordemos que app es donde configuramos todo el servidor
# dentro de esa app tenemos la propiedad JWT_SECRET_KEY y se le está asignando un valor
# finalmente activamos la función JWTManager y le pasamos como argumento la configuración que acabamos de hacer de (app)
# así configuramos la tecnología Flask_JWT debidamente para que se lea
# esa configuración que activa la función JWTManager queda guardada en la variable jwt
#///////////////////////////////////





# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200




#///////////////////////////////////////////////////
#OJO AQUÍ CREAMOS LA RUTA PARA EL LOGIN SEGURO CON JWT
#///////////////////////////////////////////////////

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None) #//// ACÁ DEFINIMOS LOS DATOS QUE RECIBIREMOS DESDE EL FRONT, EN ESTA LINEA email. 
    password = request.json.get("password", None)  #//// ACÁ DEFINIMOS LOS DATOS QUE RECIBIREMOS DESDE EL FRONT, EN ESTA LINEA password. 

    user = User.query.filter_by(email=email).first()  #//// ACÁ HAGO UNA CONSULTA ESPECÍFICA (query) PARA OBTENER LA INFORMACIÓN DE UN USUARIO EN PARTICULAR A TRAVÉS DE SU email (que es un campo dentro del modelo-tabla User), QUE SE GUARDO EN LA BASE DE DATOS (INFORMACIÓN QUE SE GENERÓ DESDE EL FRONT CUANDO EL USUARIO AGREGÓ LOS DATOS)
    print(user.email)


    if email != user.email or password != user.password: #//// OJO AQUÍ ACTIVAS LA CONDICIÓN DONDE SI EL CORREO O EL PASSWORD NO SON LOS REGISTRADOS EN LA BASE DE DATOS... (previamente al inicio indicábamos que email debe ser "test" y password debe ser "test")
        return jsonify({"msg": "Bad email or password"}), 401 #//// ... ENTONCES SE MUESTRA UN MENSAJE DE ALERTA POR ERROR EN EL email O PASSWORD

    access_token = create_access_token(identity=email) #//// ... SI AMBOS ESTÁN CORRECTOS ENTONCES ACTIVA LA FUNCIÓN create_access_token QUE GENERA EL TOKEN DE ACCESO. **** OJO **** LO HACE A TRAVÉS DE LA PROPIEDAD identity Y ASOCIA CON EL VALOR DE email QUE VIENE DESDE EL FRONT.... ENTONCES LE ASIGNA UN TOKEN...
    return jsonify(access_token=access_token)  #//// ... Y EL access_token ES JUSTO LO QUE SE MANDA COMO RESPUESTA.


#///////////////////////////////////////////////////
# OJO: AHORA PUEDO CREAR UN USUARIO DESDE ACÁ EN EL simple browser CON SU email Y password. 
# ENTONCES PUEDO IRME A POSTMAN Y PROBAR MI LOGIN CON EL MÉTODO POST
# AL HACER EL POST DEBO COLOCAR UN body json EN POSTMAN CON LOS DOS DATOS QUE INDIQUÉ PARA ESTA RUTA email Y password TAL Y COMO LOS PUSE EN EL simple browser de acá
# SI EL email Y EL password COINCIDEN CON LOS REGISTRADOS ENTONCES TE GENERA EL TOKEN DE INGRESO. 
#///////////////////////////////////////////////////









#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * •

# A ESTE PUNTO YO TENGO COMPLETAMENTE INTEGRADO JWT CON MI CODIGO 
# JWT YA ESTÁ DENTRO DE MI APLICACIÓN
# REALIZA CONSULTAS A MI BASE DE DATOS PARA VERIFICAR SI EL USARIO DE TURNO ESTÁ DEBIDAMENTE REGISTRADO EN MI APLICACIÓN
# SI ESTÁ REGISTRADO DEVUELVE UN TOKEN
# SI NO... LE DA UN MENSAJE DE ADVERTENCIA

#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * •




# >>>>>>>> AHORA PODEMOS CREAR CONTENIDO EXCLUSIVO <<<<<
# >>>>>>>>>>>>>>>>> RUTAS PROTEGIDAS <<<<<<<<<<<<<<<<<<<




#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • 
# AHORA PUEDO PROCEDER A INGRESASR A UNA RUTA PROTEGIDA (PORQUE DEBÉS AUTENTICARTE) COMO profile
# PARA ACCEDER A ESA RUTA PROTEGIDA DEBO USAR EL MÉTODO GET. 
# PERO OJO: TENGO QUE AUTENTICARME Y PARA ESO TENGO QUE IRME EN POSTMAN A Authorization 
# AHÍ SELECCIONAR bearer token Y COLOCAR EL token QUE SE TE GENERÓ (ARRIBA) CON EL LOGIN 
# UNA VEZ QUE INGRESO EL TOKEN, ENTONCES 
#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • 




#///////////////////////////////////////////////////
# OJO AQUÍ CREAMOS LAS RUTAS PROTEGIDAS / 
# ES DECIR: CONTENIDO AL QUE SE PUEDE INGRESAR SOLO SI ESTAS AUTENTICADO
# COMO MI PERFIL O MI BANDEJA DE ENTRADA
#///////////////////////////////////////////////////

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/profile", methods=["GET"])
@jwt_required() #/// OJO /// ESTE ES EL GUARDA DE LA PUERTA / AQUÍ ACTIVA LA FUNCIÓN jwt_required PARA PROTEGER ESA RUTA
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity() #/// CON ESTA FUNCIÓN JWT OBTIENE LA IDENTIDAD DEL USUARIO Y LA GUARDA EN LA VARIABLE current_user
    user = User.query.filter_by(email=current_user).first() #//// ACÁ HAGO UNA CONSULTA ESPECÍFICA (query) PARA VERIFICAR QUE EL USUARIO EXISTA EN LOS REGISTRO  ***IMPORTANTE*** ACÁ LO FILTRO POR LA PROPIEDAD email PERO APROVECHANDO QUE LA FUNCIÓN get_jwt_identity QUE OBTIENE LA IDENTIDAD DEL USUARIO... Y ESA IDENTIDAD QUEDA GUARDADA EN LA VARIABLE current_user
    if current_user != user.email:
        return jsonify({"msg":"Ud no está registrado"}), 401
   
    return jsonify(user.serialize()), 200 #//// ACÁ DOY LA RESPUESTA POSITIVA PERO NO LA PUEDO ENVIAR ASÍ NO MÁS PORQUE NECESITO QUE SE TRADUZCA A ALGO LEGIBLE PARA EL FRONT POR ESO LE APLICO EL .serialize()


if __name__ == "__main__":
    app.run()





# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)


#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * •

# YA CON ESTO LISTO PODEMOS CONECTARLO CON EL FRONTEND PARA QUE EL USUARIO REALICE SU REGISTRO Y QUEDE DEBDIAMENTE AUTENTICADO POR JWT Y REGISTRADO EN LA BASE DE DATOS

#* • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * • * •