CREATE DATABASE IF NOT EXISTS bd_examen_bdn;
USE bd_examen_bdn; 

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE,
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255),
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN DEFAULT TRUE,
    tipo ENUM('admin','usuario') DEFAULT 'usuario'
);

INSERT INTO usuarios (id, username, email, password_hash, fecha_registro, activo, tipo)
VALUES
  (1, 'admin', 'admin@example.com',
   '$2b$12$mmBWMTS2ioS8yh4nJh6SVO5Hmc31.3RkjIBwqYHK0TBBZEklovYJ2',
   '2025-11-10 20:14:28', TRUE, 'admin'),

  (2, 'carla', 'carla@gmail.com',
   '$2b$12$fKzrdj1BgV4RbybVKtfnuOLn26ICCeG8Sm7GuYQxw2R9nXcQDy9la',
   NOW(), TRUE, 'usuario');
