-- =====================================================
-- Migration V2: Invitation Status & Access Events
-- Run this to upgrade existing database
-- =====================================================

USE zkteco;

-- =====================================================
-- 1. Add Status field to PRY_Acceso
-- =====================================================
ALTER TABLE PRY_Acceso 
ADD COLUMN IF NOT EXISTS Status ENUM('ACTIVE', 'CANCELLED', 'EXPIRED', 'USED') DEFAULT 'ACTIVE',
ADD COLUMN IF NOT EXISTS UsageLimit INT DEFAULT 1,
ADD COLUMN IF NOT EXISTS UsedCount INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS CancelledAt DATETIME NULL,
ADD COLUMN IF NOT EXISTS CancelledBy VARCHAR(50) NULL;

-- =====================================================
-- 2. Create Invitations Table (enhanced tracking)
-- =====================================================
CREATE TABLE IF NOT EXISTS PRY_Invitacion (
    IDInvitacion INT AUTO_INCREMENT PRIMARY KEY,
    IDAcceso VARCHAR(50),
    CreadoPor VARCHAR(50) NOT NULL,
    NombreInvitado VARCHAR(255),
    RutInvitado VARCHAR(50),
    CorreoInvitado VARCHAR(255),
    TelefonoInvitado VARCHAR(20),
    Motivo VARCHAR(500),
    FechaInicio DATETIME NOT NULL,
    FechaFin DATETIME NOT NULL,
    IDSala INT,
    Status ENUM('ACTIVE', 'CANCELLED', 'EXPIRED', 'USED') DEFAULT 'ACTIVE',
    UsageLimit INT DEFAULT 1,
    UsedCount INT DEFAULT 0,
    CancelledAt DATETIME NULL,
    CancelledBy VARCHAR(50) NULL,
    QRCode TEXT,
    Activo TINYINT(1) DEFAULT 1,
    FechaCreacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (CreadoPor) REFERENCES PRY_Usuarios(IDUsuario),
    FOREIGN KEY (IDSala) REFERENCES PRY_Sala(IDSala),
    INDEX idx_invitacion_creador (CreadoPor),
    INDEX idx_invitacion_status (Status),
    INDEX idx_invitacion_acceso (IDAcceso)
);

-- Add TipoInvitacion (Visitante | Delivery) if missing
ALTER TABLE PRY_Invitacion ADD COLUMN TipoInvitacion VARCHAR(50) DEFAULT 'Visitante' AFTER TelefonoInvitado;

-- =====================================================
-- 3. Create Access Events Table (Scan Logging)
-- =====================================================
CREATE TABLE IF NOT EXISTS PRY_AccessEvent (
    IDEvent INT AUTO_INCREMENT PRIMARY KEY,
    IDAcceso VARCHAR(50),
    IDInvitacion INT NULL,
    DeviceSN VARCHAR(100),
    DeviceName VARCHAR(255),
    Puerta VARCHAR(100),
    ScannedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    Result ENUM('ALLOWED', 'DENIED') NOT NULL,
    Reason VARCHAR(100),
    RawData TEXT,
    Activo TINYINT(1) DEFAULT 1,
    INDEX idx_event_acceso (IDAcceso),
    INDEX idx_event_fecha (ScannedAt),
    INDEX idx_event_result (Result),
    INDEX idx_event_device (DeviceSN)
);

-- =====================================================
-- 4. Create stored procedures for invitations
-- =====================================================

DELIMITER //

-- Create invitation (TipoInvitacion = Visitante | Delivery)
DROP PROCEDURE IF EXISTS spPRY_Invitacion_Crear //
CREATE PROCEDURE spPRY_Invitacion_Crear(
    IN p_IDAcceso VARCHAR(50),
    IN p_CreadoPor VARCHAR(50),
    IN p_NombreInvitado VARCHAR(255),
    IN p_RutInvitado VARCHAR(50),
    IN p_CorreoInvitado VARCHAR(255),
    IN p_TelefonoInvitado VARCHAR(20),
    IN p_TipoInvitacion VARCHAR(50),
    IN p_Motivo VARCHAR(500),
    IN p_FechaInicio DATETIME,
    IN p_FechaFin DATETIME,
    IN p_IDSala INT,
    IN p_UsageLimit INT,
    IN p_QRCode TEXT
)
BEGIN
    INSERT INTO PRY_Invitacion (
        IDAcceso, CreadoPor, NombreInvitado, RutInvitado, CorreoInvitado,
        TelefonoInvitado, TipoInvitacion, Motivo, FechaInicio, FechaFin, IDSala, UsageLimit, QRCode
    ) VALUES (
        p_IDAcceso, p_CreadoPor, p_NombreInvitado, p_RutInvitado, p_CorreoInvitado,
        p_TelefonoInvitado, COALESCE(p_TipoInvitacion, 'Visitante'), p_Motivo, p_FechaInicio, p_FechaFin, p_IDSala, p_UsageLimit, p_QRCode
    );
    SELECT LAST_INSERT_ID() AS IDInvitacion;
END //

-- List invitations by creator
DROP PROCEDURE IF EXISTS spPRY_Invitacion_Listar //
CREATE PROCEDURE spPRY_Invitacion_Listar(IN p_CreadoPor VARCHAR(50))
BEGIN
    SELECT 
        i.IDInvitacion,
        i.IDAcceso,
        i.NombreInvitado,
        i.RutInvitado,
        i.CorreoInvitado,
        i.TelefonoInvitado,
        i.TipoInvitacion,
        i.Motivo,
        i.FechaInicio,
        i.FechaFin,
        i.IDSala,
        s.Sala,
        i.Status,
        i.UsageLimit,
        i.UsedCount,
        i.QRCode,
        i.FechaCreacion,
        i.CancelledAt,
        CASE 
            WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
            WHEN i.Status = 'USED' THEN 'USED'
            WHEN NOW() > i.FechaFin THEN 'EXPIRED'
            WHEN NOW() < i.FechaInicio THEN 'PENDING'
            ELSE 'ACTIVE'
        END AS StatusActual
    FROM PRY_Invitacion i
    LEFT JOIN PRY_Sala s ON i.IDSala = s.IDSala
    WHERE i.CreadoPor = p_CreadoPor AND i.Activo = 1
    ORDER BY i.FechaCreacion DESC;
END //

-- Get invitation by ID
DROP PROCEDURE IF EXISTS spPRY_Invitacion_Obtener //
CREATE PROCEDURE spPRY_Invitacion_Obtener(IN p_IDInvitacion INT)
BEGIN
    SELECT 
        i.*,
        s.Sala,
        CASE 
            WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
            WHEN i.Status = 'USED' THEN 'USED'
            WHEN NOW() > i.FechaFin THEN 'EXPIRED'
            WHEN NOW() < i.FechaInicio THEN 'PENDING'
            ELSE 'ACTIVE'
        END AS StatusActual
    FROM PRY_Invitacion i
    LEFT JOIN PRY_Sala s ON i.IDSala = s.IDSala
    WHERE i.IDInvitacion = p_IDInvitacion AND i.Activo = 1;
END //

-- Cancel invitation
DROP PROCEDURE IF EXISTS spPRY_Invitacion_Cancelar //
CREATE PROCEDURE spPRY_Invitacion_Cancelar(
    IN p_IDInvitacion INT,
    IN p_CancelledBy VARCHAR(50)
)
BEGIN
    DECLARE v_IDAcceso VARCHAR(50);
    
    -- Get the access ID
    SELECT IDAcceso INTO v_IDAcceso FROM PRY_Invitacion WHERE IDInvitacion = p_IDInvitacion;
    
    -- Update invitation
    UPDATE PRY_Invitacion 
    SET Status = 'CANCELLED', CancelledAt = NOW(), CancelledBy = p_CancelledBy
    WHERE IDInvitacion = p_IDInvitacion;
    
    -- Also update PRY_Acceso
    UPDATE PRY_Acceso 
    SET Status = 'CANCELLED', Activo = 0, CancelledAt = NOW(), CancelledBy = p_CancelledBy
    WHERE IDAcceso = v_IDAcceso;
    
    SELECT ROW_COUNT() AS affected;
END //

-- Mark invitation as used
DROP PROCEDURE IF EXISTS spPRY_Invitacion_MarcarUsada //
CREATE PROCEDURE spPRY_Invitacion_MarcarUsada(IN p_IDAcceso VARCHAR(50))
BEGIN
    DECLARE v_UsageLimit INT;
    DECLARE v_UsedCount INT;
    
    -- Get current counts
    SELECT UsageLimit, UsedCount INTO v_UsageLimit, v_UsedCount 
    FROM PRY_Invitacion WHERE IDAcceso = p_IDAcceso AND Activo = 1;
    
    -- Increment used count
    UPDATE PRY_Invitacion 
    SET UsedCount = UsedCount + 1,
        Status = CASE WHEN UsedCount + 1 >= UsageLimit THEN 'USED' ELSE Status END
    WHERE IDAcceso = p_IDAcceso AND Activo = 1;
    
    -- Also update PRY_Acceso
    UPDATE PRY_Acceso 
    SET UsedCount = UsedCount + 1,
        Status = CASE WHEN UsedCount + 1 >= UsageLimit THEN 'USED' ELSE Status END
    WHERE IDAcceso = p_IDAcceso;
END //

-- Validate invitation for access
DROP PROCEDURE IF EXISTS spPRY_Invitacion_Validar //
CREATE PROCEDURE spPRY_Invitacion_Validar(IN p_IDAcceso VARCHAR(50))
BEGIN
    SELECT 
        i.IDInvitacion,
        i.IDAcceso,
        i.NombreInvitado,
        i.FechaInicio,
        i.FechaFin,
        i.IDSala,
        i.Status,
        i.UsageLimit,
        i.UsedCount,
        CASE 
            WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
            WHEN i.Status = 'USED' THEN 'USED'
            WHEN i.UsedCount >= i.UsageLimit THEN 'USED'
            WHEN NOW() > i.FechaFin THEN 'EXPIRED'
            WHEN NOW() < i.FechaInicio THEN 'NOT_YET_VALID'
            ELSE 'VALID'
        END AS ValidationResult
    FROM PRY_Invitacion i
    WHERE i.IDAcceso = p_IDAcceso AND i.Activo = 1;
END //

-- Log access event
DROP PROCEDURE IF EXISTS spPRY_AccessEvent_Registrar //
CREATE PROCEDURE spPRY_AccessEvent_Registrar(
    IN p_IDAcceso VARCHAR(50),
    IN p_IDInvitacion INT,
    IN p_DeviceSN VARCHAR(100),
    IN p_DeviceName VARCHAR(255),
    IN p_Puerta VARCHAR(100),
    IN p_Result ENUM('ALLOWED', 'DENIED'),
    IN p_Reason VARCHAR(100),
    IN p_RawData TEXT
)
BEGIN
    INSERT INTO PRY_AccessEvent (
        IDAcceso, IDInvitacion, DeviceSN, DeviceName, Puerta, Result, Reason, RawData
    ) VALUES (
        p_IDAcceso, p_IDInvitacion, p_DeviceSN, p_DeviceName, p_Puerta, p_Result, p_Reason, p_RawData
    );
    SELECT LAST_INSERT_ID() AS IDEvent;
END //

-- Get access events for invitation
DROP PROCEDURE IF EXISTS spPRY_AccessEvent_Listar //
CREATE PROCEDURE spPRY_AccessEvent_Listar(IN p_IDInvitacion INT)
BEGIN
    SELECT * FROM PRY_AccessEvent 
    WHERE IDInvitacion = p_IDInvitacion 
    ORDER BY ScannedAt DESC;
END //

DELIMITER ;

-- =====================================================
-- 5. Update indexes
-- =====================================================
CREATE INDEX IF NOT EXISTS idx_acceso_status ON PRY_Acceso(Status);
