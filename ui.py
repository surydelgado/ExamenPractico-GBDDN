import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from db_mysql import get_mysql
from db_mongo import get_mongo
import bcrypt
import re
from datetime import datetime
from dotenv import load_dotenv
import socket

load_dotenv()


class App:
    def __init__(self):
        self.user = None
        self.mysql = get_mysql()
        self.mongo = get_mongo()

        if self.mysql is None or self.mongo is None:
            messagebox.showerror("Error de Conexión", "No se pudo conectar a las bases de datos")
            return

        self.root = tk.Tk()
        self.root.title("Sistema de Autenticación")
        self.root.geometry("400x400")
        self.root.resizable(False, False)

        self.show_login()
        self.root.mainloop()

    # INTERFAZ 
    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def center_label(self, text, size=16):
        lbl = tk.Label(self.root, text=text, font=("Arial", size, "bold"))
        lbl.pack(pady=10)

    #  FUNCIONES AUXILIARES
    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verificar_password(self, password, password_hash):
        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except Exception:
            return False

    def validar_email(self, email):
        return re.match(r"[^@]+@[^@]+\.[^@]+", email)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "unknown"

    # LOGIN 
    def show_login(self):
        self.clear()
        self.center_label("Inicio de Sesión")

        tk.Label(self.root, text="Usuario o Email:", font=("Arial", 11)).pack()
        self.username = tk.Entry(self.root, width=35)
        self.username.pack(pady=5)

        tk.Label(self.root, text="Contraseña:", font=("Arial", 11)).pack()
        self.password = tk.Entry(self.root, width=35, show="*")
        self.password.pack(pady=5)

        tk.Button(self.root, text="Iniciar Sesión", command=self.login, width=20).pack(pady=10)
        tk.Button(self.root, text="Registrarse", command=self.show_register).pack(pady=3)
        tk.Button(self.root, text="Recuperar Contraseña", command=self.password_recovery).pack(pady=3)

    def login(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Debes ingresar usuario y contraseña.")
            return

        cursor = self.mysql.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM usuarios WHERE username=%s OR email=%s", (username, username))
            user = cursor.fetchone()
        except Exception as e:
            messagebox.showerror("Error BD", f"Error consultando MySQL: {e}")
            return
        finally:
            cursor.close()

        if user and self.verificar_password(password, user['password_hash']):
            self.user = user
            # Registrar log en MongoDB
            self.mongo.logs.insert_one({
                "usuario": username,
                "accion": "login_exitoso",
                "fecha": datetime.utcnow(),
                "ip": self.get_local_ip()
            })
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Credenciales inválidas")

    # REGISTRO
    def show_register(self):
        self.clear()
        self.center_label("Registro de Usuario")

        tk.Label(self.root, text="Usuario:", font=("Arial", 11)).pack()
        self.reg_user = tk.Entry(self.root, width=35)
        self.reg_user.pack(pady=3)

        tk.Label(self.root, text="Correo:", font=("Arial", 11)).pack()
        self.reg_mail = tk.Entry(self.root, width=35)
        self.reg_mail.pack(pady=3)

        tk.Label(self.root, text="Contraseña:", font=("Arial", 11)).pack()
        self.reg_pass = tk.Entry(self.root, width=35, show="*")
        self.reg_pass.pack(pady=3)

        tk.Button(self.root, text="Registrar", command=self.register, width=20).pack(pady=10)
        tk.Button(self.root, text="Volver", command=self.show_login).pack()

    def register(self):
        username = self.reg_user.get().strip()
        email = self.reg_mail.get().strip()
        password = self.reg_pass.get().strip()

        if not username or not email or not password:
            messagebox.showerror("Error", "Completa todos los campos.")
            return

        if not self.validar_email(email):
            messagebox.showerror("Error", "Correo electrónico inválido.")
            return

        if len(password) < 6:
            messagebox.showerror("Error", "La contraseña debe tener al menos 6 caracteres.")
            return

        cursor = self.mysql.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE username=%s OR email=%s", (username, email))
        if cursor.fetchone():
            messagebox.showerror("Error", "El usuario o correo ya existen.")
            return

        hashed = self.hash_password(password)

        try:
            cursor.execute(
                "INSERT INTO usuarios(username, email, password_hash, tipo) VALUES (%s,%s,%s,%s)",
                (username, email, hashed.decode(), "usuario")
            )
            self.mysql.commit()

            self.mongo.usuarios.insert_one({
                "username": username,
                "email": email,
                "password_hash": hashed.decode(),
                "fecha_registro": datetime.utcnow(),
                "activo": True,
                "tipo": "usuario"
            })

            self.mongo.logs.insert_one({
                "usuario": username,
                "accion": "registro",
                "fecha": datetime.utcnow(),
                "ip": self.get_local_ip()
            })

            messagebox.showinfo("Éxito", "Usuario registrado correctamente.")
            self.show_login()

        except Exception as e:
            self.mysql.rollback()
            messagebox.showerror("Error", f"No se pudo registrar el usuario: {e}")
        finally:
            cursor.close()

    #  MENÚ PRINCIPAL
    def show_main_menu(self):
        self.clear()
        tipo = self.user.get('tipo', 'usuario')
        tk.Label(self.root, text=f"Bienvenido {self.user['username']} ({tipo})", font=("Arial", 14)).pack(pady=10)

        tk.Button(self.root, text="Ver Perfil", width=25, command=self.view_profile).pack(pady=3)
        tk.Button(self.root, text="Editar Perfil", width=25, command=self.edit_profile).pack(pady=3)
        if tipo == "admin":
            tk.Button(self.root, text="Gestionar Usuarios", width=25, command=self.manage_users).pack(pady=3)

        tk.Button(self.root, text="Cerrar Sesión", width=25, command=self.logout).pack(pady=10)

    # FUNCIONES DE USUARIO 
    def view_profile(self):
        info = f"Usuario: {self.user['username']}\nEmail: {self.user['email']}\nActivo: {'Sí' if self.user['activo'] else 'No'}"
        messagebox.showinfo("Perfil", info)

    def edit_profile(self):
        new_email = simpledialog.askstring("Editar Perfil", "Nuevo correo electrónico:", initialvalue=self.user['email'])
        new_pass = simpledialog.askstring("Editar Perfil", "Nueva contraseña (opcional):", show="*")

        if not new_email or not self.validar_email(new_email):
            messagebox.showerror("Error", "Correo inválido.")
            return

        hashed = self.hash_password(new_pass) if new_pass else self.user['password_hash']

        cursor = self.mysql.cursor()
        try:
            cursor.execute("UPDATE usuarios SET email=%s, password_hash=%s WHERE id=%s",
                           (new_email, hashed.decode(), self.user['id']))
            self.mysql.commit()

            self.mongo.usuarios.update_one(
                {"username": self.user['username']},
                {"$set": {"email": new_email, "password_hash": hashed.decode()}}
            )

            self.mongo.logs.insert_one({
                "usuario": self.user['username'],
                "accion": "editar_perfil",
                "fecha": datetime.utcnow()
            })

            messagebox.showinfo("Éxito", "Perfil actualizado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo actualizar: {e}")
        finally:
            cursor.close()

    def password_recovery(self):
        email = simpledialog.askstring("Recuperar Contraseña", "Ingresa tu correo electrónico:")
        if not email:
            return

        cursor = self.mysql.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user:
            messagebox.showerror("Error", "Correo no registrado.")
            return

        new_password = simpledialog.askstring("Nueva Contraseña", "Ingresa tu nueva contraseña:", show="*")
        if not new_password or len(new_password) < 6:
            messagebox.showerror("Error", "Contraseña inválida.")
            return

        hashed = self.hash_password(new_password)
        cursor.execute("UPDATE usuarios SET password_hash=%s WHERE email=%s", (hashed.decode(), email))
        self.mysql.commit()
        self.mongo.usuarios.update_one({"email": email}, {"$set": {"password_hash": hashed.decode()}})

        self.mongo.logs.insert_one({
            "usuario": user['username'],
            "accion": "recuperacion_contrasena",
            "fecha": datetime.utcnow()
        })

        messagebox.showinfo("Éxito", "Contraseña actualizada correctamente.")

    def logout(self):
        self.mongo.logs.insert_one({
            "usuario": self.user['username'],
            "accion": "logout",
            "fecha": datetime.utcnow()
        })
        self.user = None
        self.show_login()

    # ADMIN 
    def manage_users(self):
        self.clear()
        self.center_label("Gestión de Usuarios")

        tree = ttk.Treeview(self.root, columns=("id", "username", "email", "activo", "tipo"), show="headings")
        for col in ("id", "username", "email", "activo", "tipo"):
            tree.heading(col, text=col)
            tree.column(col, width=80)
        tree.pack(pady=10, fill="both", expand=True)

        cursor = self.mysql.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, activo, tipo FROM usuarios")
        for row in cursor.fetchall():
            tree.insert("", "end", values=(row["id"], row["username"], row["email"],
                                           "Sí" if row["activo"] else "No", row["tipo"]))
        cursor.close()

        def toggle_active():
            selected = tree.focus()
            if not selected:
                messagebox.showwarning("Advertencia", "Selecciona un usuario.")
                return
            data = tree.item(selected)['values']
            user_id, username, _, activo, _ = data
            nuevo_estado = not (activo == "Sí")
            cur = self.mysql.cursor()
            cur.execute("UPDATE usuarios SET activo=%s WHERE id=%s", (nuevo_estado, user_id))
            self.mysql.commit()
            cur.close()
            messagebox.showinfo("Éxito", f"Usuario {username} {'activado' if nuevo_estado else 'desactivado'}.")
            self.manage_users()

        def eliminar_usuario():
            selected = tree.focus()
            if not selected:
                messagebox.showwarning("Advertencia", "Selecciona un usuario.")
                return
            data = tree.item(selected)['values']
            user_id, username = data[0], data[1]
            if messagebox.askyesno("Confirmar", f"¿Eliminar usuario {username}?"):
                cur = self.mysql.cursor()
                cur.execute("DELETE FROM usuarios WHERE id=%s", (user_id,))
                self.mysql.commit()
                cur.close()
                self.mongo.usuarios.delete_one({"username": username})
                messagebox.showinfo("Éxito", "Usuario eliminado.")
                self.manage_users()

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Activar/Desactivar", command=toggle_active).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Eliminar", command=eliminar_usuario).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Volver", command=self.show_main_menu).grid(row=0, column=2, padx=5)


