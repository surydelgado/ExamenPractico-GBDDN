# 🧩 Proyecto de Sistema de Autenticación

## 📘 Descripción

Este proyecto consiste en un **sistema de autenticación básico** utilizando **MySQL** para el almacenamiento de usuarios y **MongoDB** para gestionar logs y actividades.  
El sistema permite el **registro de nuevos usuarios**, **inicio de sesión**, **recuperación de contraseña** y **gestión de usuarios para administradores**.

---

## 📂 Estructura del Proyecto

```
├── main.py              # Archivo principal que ejecuta la aplicación
├── ui.py                # Contiene la interfaz gráfica del usuario (Tkinter)
├── db_mysql.py          # Maneja la conexión y operaciones con MySQL
├── db_mongo.py          # Maneja la conexión y operaciones con MongoDB
├── requirements.txt     # Lista de dependencias necesarias
├── .env                 # Variables de entorno (credenciales de las BD)
├── sql/                 # Scripts SQL para crear tablas en MySQL
└── mongo/               # Configuraciones y datos relacionados con MongoDB
```

---

## 🧰 Requisitos

- **Python 3.x**
- **MySQL** (para gestión de usuarios)
- **MongoDB** (para almacenar logs y registros de actividades)
- **Tkinter** (para la interfaz gráfica)

---

## 📦 Instalación de dependencias

Ejecuta el siguiente comando para instalar todo lo necesario:

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuración

### 1. Archivo `.env`

Crea un archivo llamado `.env` en la raíz del proyecto y configura tus credenciales:

```bash
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=tu_contraseña
MYSQL_DATABASE=nombre_base_de_datos

MONGO_URI=mongodb+srv://usuario:contraseña@cluster.mongodb.net
MONGO_DATABASE=nombre_base_de_datos_mongo
```

---

### 2. Base de Datos MySQL

Ejecuta los scripts SQL ubicados en la carpeta `sql/` para crear la estructura de la base de datos:

```bash
mysql -u root -p < sql/crear_base_de_datos.sql
```

---

### 3. Base de Datos MongoDB

La conexión se establece automáticamente mediante la URI configurada en el archivo `.env`.

---

## ▶️ Ejecución del Proyecto

Para iniciar el sistema, simplemente ejecuta:

```bash
python main.py
```

---

## 🚀 Funcionalidades

### 👤 Registro de Usuario
Los usuarios pueden registrarse con nombre, correo y contraseña.  
Las contraseñas se almacenan de forma segura utilizando **bcrypt**.

### 🔐 Inicio de Sesión
Permite a los usuarios iniciar sesión con sus credenciales.

### 🔁 Recuperación de Contraseña
Los usuarios pueden recuperar su contraseña ingresando su correo registrado.  
Si el correo existe, se les permitirá establecer una nueva contraseña.

### 🧑‍💼 Gestión de Usuarios (Solo Administradores)
Los administradores pueden:
- Ver todos los usuarios registrados  
- Activar o desactivar cuentas  
- Editar información de usuarios  

---

## 🧩 Tecnologías Utilizadas

- Python 3  
- MySQL  
- MongoDB  
- Tkinter  
- bcrypt  
- python-dotenv  

---

## 👨‍💻 Autor

Desarrollado por **[Tu Nombre Aquí]**  
📧 Contacto: [tuemail@ejemplo.com]

---

## 🪪 Licencia

Este proyecto está bajo la licencia **MIT**.
