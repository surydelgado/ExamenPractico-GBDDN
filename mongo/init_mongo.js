use bd_examen_bdn;

db.createCollection("usuarios");
db.createCollection("logs");
db.usuarios.drop();

db.usuarios.insertMany([
  {
    username: "admin",
    email: "admin@example.com",
    password_hash: "$2b$12$mmBWMTS2ioS8yh4nJh6SVO5Hmc31.3RkjIBwqYHK0TBBZEklovYJ2",
    fecha_registro: ISODate("2025-11-10T20:14:28Z"),
    activo: true,
    tipo: "admin"
  },
  {
    username: "carla",
    email: "carla@gmail.com",
    password_hash: "$2b$12$fKzrdj1BgV4RbybVKtfnuOLn26ICCeG8Sm7GuYQxw2R9nXcQDy9la",
    fecha_registro: new Date(),
    activo: true,
    tipo: "usuario"}
 ]);