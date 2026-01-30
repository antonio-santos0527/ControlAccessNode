-- =====================================================
-- Control de Acceso - Stored Procedures
-- =====================================================

USE zkteco;

DELIMITER //

-- =====================================================
-- USER AUTHENTICATION PROCEDURES
-- =====================================================

-- Get user by ID (for login; includes IDSala, FechaInicioValidez, FechaFinValidez)
DROP PROCEDURE IF EXISTS spPRY_Usuarios_ObtenerPorID //
CREATE PROCEDURE spPRY_Usuarios_ObtenerPorID(IN p_IDUsuario VARCHAR(50))
BEGIN
    SELECT 
        IDUsuario,
        NombreUsuario,
        Passwd,
        CorreoElectronico,
        Telefono,
        IDRol,
        IDSala,
        FechaInicioValidez,
        FechaFinValidez,
        PassTemp
    FROM PRY_Usuarios
    WHERE IDUsuario = p_IDUsuario AND Activo = 1;
END //

-- Change user password
DROP PROCEDURE IF EXISTS spPRY_Usuarios_CambiarPass //
CREATE PROCEDURE spPRY_Usuarios_CambiarPass(
    IN p_IDUsuario VARCHAR(50),
    IN p_Password VARCHAR(255)
)
BEGIN
    UPDATE PRY_Usuarios 
    SET Passwd = MD5(p_Password), PassTemp = 0
    WHERE IDUsuario = p_IDUsuario;
END //

-- =====================================================
-- USER MANAGEMENT PROCEDURES
-- =====================================================

-- List all users
DROP PROCEDURE IF EXISTS spPRY_Usuario_Listar //
CREATE PROCEDURE spPRY_Usuario_Listar()
BEGIN
    SELECT 
        u.IDUsuario,
        u.NombreUsuario,
        u.CorreoElectronico,
        u.Telefono,
        u.IDRol,
        u.IDSala,
        u.FechaInicioValidez,
        u.FechaFinValidez,
        r.Descripcion AS Rol,
        a.IDAcceso
    FROM PRY_Usuarios u
    LEFT JOIN PRY_Rol r ON u.IDRol = r.IDRol
    LEFT JOIN PRY_Acceso a ON u.IDUsuario = a.IDUsuario AND a.Activo = 1
    WHERE u.Activo = 1
    ORDER BY u.NombreUsuario;
END //

-- Save/Create user (IDSala, FechaInicioValidez, FechaFinValidez for Residente/Personal)
DROP PROCEDURE IF EXISTS spPRY_Usuario_Guardar //
CREATE PROCEDURE spPRY_Usuario_Guardar(
    IN p_Rut VARCHAR(50),
    IN p_Nombre VARCHAR(255),
    IN p_Passwd VARCHAR(255),
    IN p_Correo VARCHAR(255),
    IN p_Telefono VARCHAR(20),
    IN p_IDRol INT,
    IN p_IDSala INT,
    IN p_FechaInicioValidez DATETIME,
    IN p_FechaFinValidez DATETIME
)
BEGIN
    INSERT INTO PRY_Usuarios (IDUsuario, NombreUsuario, Passwd, CorreoElectronico, Telefono, IDRol, IDSala, FechaInicioValidez, FechaFinValidez, PassTemp)
    VALUES (p_Rut, p_Nombre, MD5(p_Passwd), p_Correo, p_Telefono, p_IDRol, p_IDSala, p_FechaInicioValidez, p_FechaFinValidez, 0)
    ON DUPLICATE KEY UPDATE
        NombreUsuario = p_Nombre,
        CorreoElectronico = p_Correo,
        Telefono = p_Telefono,
        IDRol = p_IDRol,
        IDSala = p_IDSala,
        FechaInicioValidez = p_FechaInicioValidez,
        FechaFinValidez = p_FechaFinValidez;
END //

-- Delete user
DROP PROCEDURE IF EXISTS spPRY_Usuario_Eliminar //
CREATE PROCEDURE spPRY_Usuario_Eliminar(IN p_IDUsuario VARCHAR(50))
BEGIN
    UPDATE PRY_Usuarios SET Activo = 0 WHERE IDUsuario = p_IDUsuario;
    UPDATE PRY_Acceso SET Activo = 0 WHERE IDUsuario = p_IDUsuario;
END //

-- Get user for WebSocket
DROP PROCEDURE IF EXISTS spPRY_Usuario_ObtenerWS //
CREATE PROCEDURE spPRY_Usuario_ObtenerWS(IN p_Rut VARCHAR(50))
BEGIN
    SELECT 
        u.IDUsuario,
        u.NombreUsuario,
        a.IDAcceso,
        a.Payload
    FROM PRY_Usuarios u
    LEFT JOIN PRY_Acceso a ON u.IDUsuario = a.IDUsuario AND a.Activo = 1
    WHERE u.IDUsuario = p_Rut AND u.Activo = 1;
END //

-- =====================================================
-- ROLE PROCEDURES
-- =====================================================

-- Get roles for select dropdown
DROP PROCEDURE IF EXISTS spPRY_Rol_Select //
CREATE PROCEDURE spPRY_Rol_Select(IN p_IDUsuario VARCHAR(50))
BEGIN
    DECLARE userRol INT;
    
    SELECT IDRol INTO userRol FROM PRY_Usuarios WHERE IDUsuario = p_IDUsuario;
    
    SELECT IDRol AS Restriccion, Descripcion
    FROM PRY_Rol
    WHERE Activo = 1 AND Restriccion >= COALESCE(userRol, 1)
    ORDER BY Restriccion;
END //

-- Get roles for mobile
DROP PROCEDURE IF EXISTS spPRY_Mobile_Rol_Select //
CREATE PROCEDURE spPRY_Mobile_Rol_Select(IN p_IDUsuario VARCHAR(50))
BEGIN
    DECLARE userRol INT;
    
    SELECT IDRol INTO userRol FROM PRY_Usuarios WHERE IDUsuario = p_IDUsuario;
    
    SELECT IDRol AS value, Descripcion AS label
    FROM PRY_Rol
    WHERE Activo = 1 AND Restriccion >= COALESCE(userRol, 1)
    ORDER BY Restriccion;
END //

-- =====================================================
-- ACCESS CONTROL PROCEDURES
-- =====================================================

-- List all access IDs
DROP PROCEDURE IF EXISTS spPRY_IDAcceso_Listar //
CREATE PROCEDURE spPRY_IDAcceso_Listar()
BEGIN
    SELECT IDAcceso FROM PRY_Acceso WHERE Activo = 1;
END //

-- Add user access link
DROP PROCEDURE IF EXISTS spPRY_Usuario_AgregarEnlace //
CREATE PROCEDURE spPRY_Usuario_AgregarEnlace(
    IN p_IDAcceso VARCHAR(50),
    IN p_IDUsuario VARCHAR(50),
    IN p_Payload JSON
)
BEGIN
    INSERT INTO PRY_Acceso (IDAcceso, IDUsuario, Payload)
    VALUES (p_IDAcceso, p_IDUsuario, p_Payload)
    ON DUPLICATE KEY UPDATE
        Payload = p_Payload,
        Activo = 1;
END //

-- Get user access link
DROP PROCEDURE IF EXISTS spPRY_Usuario_Enlace_Listar //
CREATE PROCEDURE spPRY_Usuario_Enlace_Listar(IN p_IDUsuario VARCHAR(50))
BEGIN
    SELECT IDAcceso, IDUsuario, Payload
    FROM PRY_Acceso
    WHERE IDUsuario = p_IDUsuario AND Activo = 1;
END //

-- Get access by user
DROP PROCEDURE IF EXISTS spPRY_Acceso_ObtenerPorUsuario //
CREATE PROCEDURE spPRY_Acceso_ObtenerPorUsuario(IN p_IDUsuario VARCHAR(50))
BEGIN
    SELECT IDAcceso, IDUsuario, Payload
    FROM PRY_Acceso
    WHERE IDUsuario = p_IDUsuario AND Activo = 1;
END //

-- Get access by access ID
DROP PROCEDURE IF EXISTS spPRY_Acceso_ObtenerPorAcceso //
CREATE PROCEDURE spPRY_Acceso_ObtenerPorAcceso(IN p_IDAcceso VARCHAR(50))
BEGIN
    SELECT 
        a.IDAcceso, 
        a.IDUsuario, 
        a.Payload,
        u.NombreUsuario
    FROM PRY_Acceso a
    LEFT JOIN PRY_Usuarios u ON a.IDUsuario = u.IDUsuario
    WHERE a.IDAcceso = p_IDAcceso AND a.Activo = 1;
END //

-- Delete access
DROP PROCEDURE IF EXISTS spPRY_Acceso_Eliminar //
CREATE PROCEDURE spPRY_Acceso_Eliminar(IN p_IDAcceso VARCHAR(50))
BEGIN
    UPDATE PRY_Acceso SET Activo = 0 WHERE IDAcceso = p_IDAcceso;
END //

-- =====================================================
-- BUILDING PROCEDURES
-- =====================================================

-- List buildings
DROP PROCEDURE IF EXISTS spPRY_Edificio_Listar //
CREATE PROCEDURE spPRY_Edificio_Listar()
BEGIN
    SELECT IDEdificio, Edificio
    FROM PRY_Edificio
    WHERE Activo = 1
    ORDER BY Edificio;
END //

-- Save building
DROP PROCEDURE IF EXISTS spPRY_Edificio_Guardar //
CREATE PROCEDURE spPRY_Edificio_Guardar(IN p_Edificio VARCHAR(255))
BEGIN
    INSERT INTO PRY_Edificio (Edificio) VALUES (p_Edificio);
END //

-- Update building
DROP PROCEDURE IF EXISTS spPRY_Edificio_Actualizar //
CREATE PROCEDURE spPRY_Edificio_Actualizar(
    IN p_IDEdificio INT,
    IN p_Edificio VARCHAR(255)
)
BEGIN
    UPDATE PRY_Edificio SET Edificio = p_Edificio WHERE IDEdificio = p_IDEdificio;
END //

-- Delete building
DROP PROCEDURE IF EXISTS spPRY_Edificio_Eliminar //
CREATE PROCEDURE spPRY_Edificio_Eliminar(IN p_IDEdificio INT)
BEGIN
    UPDATE PRY_Edificio SET Activo = 0 WHERE IDEdificio = p_IDEdificio;
END //

-- =====================================================
-- FLOOR PROCEDURES
-- =====================================================

-- List floors
DROP PROCEDURE IF EXISTS spPRY_Piso_Listar //
CREATE PROCEDURE spPRY_Piso_Listar()
BEGIN
    SELECT 
        p.IDPiso,
        p.IDEdificio,
        e.Edificio,
        p.Piso
    FROM PRY_Piso p
    JOIN PRY_Edificio e ON p.IDEdificio = e.IDEdificio
    WHERE p.Activo = 1 AND e.Activo = 1
    ORDER BY e.Edificio, p.Piso;
END //

-- Save floor
DROP PROCEDURE IF EXISTS spPRY_Piso_Guardar //
CREATE PROCEDURE spPRY_Piso_Guardar(
    IN p_IDEdificio INT,
    IN p_Piso VARCHAR(100)
)
BEGIN
    INSERT INTO PRY_Piso (IDEdificio, Piso) VALUES (p_IDEdificio, p_Piso);
END //

-- Update floor
DROP PROCEDURE IF EXISTS spPRY_Piso_Actualizar //
CREATE PROCEDURE spPRY_Piso_Actualizar(
    IN p_IDPiso INT,
    IN p_IDEdificio INT,
    IN p_Piso VARCHAR(100)
)
BEGIN
    UPDATE PRY_Piso 
    SET IDEdificio = p_IDEdificio, Piso = p_Piso 
    WHERE IDPiso = p_IDPiso;
END //

-- Delete floor
DROP PROCEDURE IF EXISTS spPRY_Piso_Eliminar //
CREATE PROCEDURE spPRY_Piso_Eliminar(IN p_IDPiso INT)
BEGIN
    UPDATE PRY_Piso SET Activo = 0 WHERE IDPiso = p_IDPiso;
END //

-- =====================================================
-- ROOM PROCEDURES
-- =====================================================

-- List rooms
DROP PROCEDURE IF EXISTS spPRY_Sala_Listar //
CREATE PROCEDURE spPRY_Sala_Listar()
BEGIN
    SELECT 
        s.IDSala,
        s.IDPiso,
        p.Piso,
        s.Sala,
        e.IDEdificio,
        e.Edificio
    FROM PRY_Sala s
    JOIN PRY_Piso p ON s.IDPiso = p.IDPiso
    JOIN PRY_Edificio e ON p.IDEdificio = e.IDEdificio
    WHERE s.Activo = 1 AND p.Activo = 1 AND e.Activo = 1
    ORDER BY e.Edificio, p.Piso, s.Sala;
END //

-- Save room
DROP PROCEDURE IF EXISTS spPRY_Sala_Guardar //
CREATE PROCEDURE spPRY_Sala_Guardar(
    IN p_IDPiso INT,
    IN p_Sala VARCHAR(255)
)
BEGIN
    INSERT INTO PRY_Sala (IDPiso, Sala) VALUES (p_IDPiso, p_Sala);
END //

-- Update room
DROP PROCEDURE IF EXISTS spPRY_Sala_Actualizar //
CREATE PROCEDURE spPRY_Sala_Actualizar(
    IN p_IDSala INT,
    IN p_IDPiso INT,
    IN p_Sala VARCHAR(255)
)
BEGIN
    UPDATE PRY_Sala 
    SET IDPiso = p_IDPiso, Sala = p_Sala 
    WHERE IDSala = p_IDSala;
END //

-- Delete room
DROP PROCEDURE IF EXISTS spPRY_Sala_Eliminar //
CREATE PROCEDURE spPRY_Sala_Eliminar(IN p_IDSala INT)
BEGIN
    UPDATE PRY_Sala SET Activo = 0 WHERE IDSala = p_IDSala;
END //

-- =====================================================
-- LOCATION/DEVICE PROCEDURES
-- =====================================================

-- List locations
DROP PROCEDURE IF EXISTS spPRY_Ubicacion_Listar //
CREATE PROCEDURE spPRY_Ubicacion_Listar()
BEGIN
    SELECT 
        u.IDUbicacion,
        u.IDSala,
        s.Sala,
        u.SN,
        u.Puerta,
        p.IDPiso,
        p.Piso,
        e.IDEdificio,
        e.Edificio
    FROM PRY_Ubicacion u
    JOIN PRY_Sala s ON u.IDSala = s.IDSala
    JOIN PRY_Piso p ON s.IDPiso = p.IDPiso
    JOIN PRY_Edificio e ON p.IDEdificio = e.IDEdificio
    WHERE u.Activo = 1 AND s.Activo = 1 AND p.Activo = 1 AND e.Activo = 1
    ORDER BY e.Edificio, p.Piso, s.Sala;
END //

-- Save location
DROP PROCEDURE IF EXISTS spPRY_Ubicacion_Guardar //
CREATE PROCEDURE spPRY_Ubicacion_Guardar(
    IN p_IDSala INT,
    IN p_SN VARCHAR(100),
    IN p_Puerta VARCHAR(100)
)
BEGIN
    INSERT INTO PRY_Ubicacion (IDSala, SN, Puerta) VALUES (p_IDSala, p_SN, p_Puerta);
END //

-- Delete location
DROP PROCEDURE IF EXISTS spPRY_Ubicacion_Eliminar //
CREATE PROCEDURE spPRY_Ubicacion_Eliminar(IN p_IDUbicacion INT)
BEGIN
    UPDATE PRY_Ubicacion SET Activo = 0 WHERE IDUbicacion = p_IDUbicacion;
END //

-- Get location by SN and door
DROP PROCEDURE IF EXISTS spPRY_Ubicacion_ObtenerPorSNPuerta //
CREATE PROCEDURE spPRY_Ubicacion_ObtenerPorSNPuerta(
    IN p_SN VARCHAR(100),
    IN p_Puerta VARCHAR(100)
)
BEGIN
    SELECT 
        u.IDUbicacion,
        u.IDSala,
        s.Sala,
        u.SN,
        u.Puerta
    FROM PRY_Ubicacion u
    JOIN PRY_Sala s ON u.IDSala = s.IDSala
    WHERE u.SN = p_SN AND u.Puerta = p_Puerta AND u.Activo = 1;
END //

-- =====================================================
-- EMPLOYEE PROCEDURES
-- =====================================================

-- List employees
DROP PROCEDURE IF EXISTS spPRY_Emp_Listar //
CREATE PROCEDURE spPRY_Emp_Listar()
BEGIN
    SELECT 
        IDEmp,
        IDUsuario,
        Nombre,
        CardNo,
        Fingerprint,
        Photo
    FROM PRY_Emp
    WHERE Activo = 1
    ORDER BY Nombre;
END //

-- Save employee
DROP PROCEDURE IF EXISTS spPRY_Emp_Guardar //
CREATE PROCEDURE spPRY_Emp_Guardar(
    IN p_IDUsuario VARCHAR(50),
    IN p_Nombre VARCHAR(255),
    IN p_CardNo VARCHAR(100),
    IN p_Fingerprint TEXT,
    IN p_Photo TEXT,
    IN p_Extra1 VARCHAR(255),
    IN p_Extra2 VARCHAR(255)
)
BEGIN
    INSERT INTO PRY_Emp (IDUsuario, Nombre, CardNo, Fingerprint, Photo)
    VALUES (p_IDUsuario, p_Nombre, p_CardNo, p_Fingerprint, p_Photo)
    ON DUPLICATE KEY UPDATE
        Nombre = p_Nombre,
        CardNo = p_CardNo,
        Fingerprint = COALESCE(p_Fingerprint, Fingerprint),
        Photo = COALESCE(p_Photo, Photo);
END //

-- Delete employee
DROP PROCEDURE IF EXISTS spPRY_Emp_Eliminar //
CREATE PROCEDURE spPRY_Emp_Eliminar(IN p_IDUsuario VARCHAR(50))
BEGIN
    UPDATE PRY_Emp SET Activo = 0 WHERE IDUsuario = p_IDUsuario;
END //

-- =====================================================
-- FINGERPRINT PROCEDURES
-- =====================================================

-- Insert fingerprint via WebSocket
DROP PROCEDURE IF EXISTS spPRY_Huella_InsertarWS //
CREATE PROCEDURE spPRY_Huella_InsertarWS(
    IN p_IDUsuario VARCHAR(50),
    IN p_FingerID INT,
    IN p_Fingerprint TEXT
)
BEGIN
    INSERT INTO PRY_Huella (IDUsuario, FingerID, Fingerprint)
    VALUES (p_IDUsuario, p_FingerID, p_Fingerprint)
    ON DUPLICATE KEY UPDATE
        Fingerprint = p_Fingerprint;
END //

-- =====================================================
-- VISIT PROCEDURES
-- =====================================================

-- Add visit
DROP PROCEDURE IF EXISTS spPRY_Mobile_Visita_Agregar //
CREATE PROCEDURE spPRY_Mobile_Visita_Agregar(
    IN p_IDUsuario VARCHAR(50),
    IN p_NombreVisitante VARCHAR(255),
    IN p_RutVisitante VARCHAR(50),
    IN p_Motivo VARCHAR(500),
    IN p_FechaInicio DATETIME,
    IN p_FechaFin DATETIME,
    IN p_IDSala INT
)
BEGIN
    INSERT INTO PRY_Visita (IDUsuario, NombreVisitante, RutVisitante, Motivo, FechaInicio, FechaFin, IDSala)
    VALUES (p_IDUsuario, p_NombreVisitante, p_RutVisitante, p_Motivo, p_FechaInicio, p_FechaFin, p_IDSala);
END //

-- Update visit
DROP PROCEDURE IF EXISTS spPRY_Mobile_Visita_Actualizar //
CREATE PROCEDURE spPRY_Mobile_Visita_Actualizar(
    IN p_IDVisita INT,
    IN p_NombreVisitante VARCHAR(255),
    IN p_RutVisitante VARCHAR(50),
    IN p_Motivo VARCHAR(500),
    IN p_FechaInicio DATETIME,
    IN p_FechaFin DATETIME,
    IN p_IDSala INT
)
BEGIN
    UPDATE PRY_Visita 
    SET NombreVisitante = p_NombreVisitante,
        RutVisitante = p_RutVisitante,
        Motivo = p_Motivo,
        FechaInicio = p_FechaInicio,
        FechaFin = p_FechaFin,
        IDSala = p_IDSala
    WHERE IDVisita = p_IDVisita;
END //

-- =====================================================
-- LOG PROCEDURES
-- =====================================================

-- Save log entry
DROP PROCEDURE IF EXISTS spPRY_Log_Guardar //
CREATE PROCEDURE spPRY_Log_Guardar(
    IN p_Funcion VARCHAR(255),
    IN p_Linea INT,
    IN p_Request TEXT
)
BEGIN
    INSERT INTO PRY_Log (Funcion, Linea, Request) VALUES (p_Funcion, p_Linea, p_Request);
END //

DELIMITER ;
