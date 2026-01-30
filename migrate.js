/**
 * Database Migration Script
 * Run: node migrate.js
 */

require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS ? atob(process.env.DB_PASS) : '',
  database: process.env.DB_DABS || 'zkteco',
  multipleStatements: true
};

async function runMigration() {
  let connection;
  
  console.log('\n========================================');
  console.log('  Database Migration V2');
  console.log('========================================\n');

  try {
    console.log('Connecting to database...');
    connection = await mysql.createConnection(config);
    console.log('Connected!\n');

    // Add columns to PRY_Acceso if they don't exist
    console.log('Step 1: Updating PRY_Acceso table...');
    
    const columnsToAdd = [
      { name: 'Status', sql: "ADD COLUMN Status ENUM('ACTIVE', 'CANCELLED', 'EXPIRED', 'USED') DEFAULT 'ACTIVE'" },
      { name: 'UsageLimit', sql: "ADD COLUMN UsageLimit INT DEFAULT 1" },
      { name: 'UsedCount', sql: "ADD COLUMN UsedCount INT DEFAULT 0" },
      { name: 'CancelledAt', sql: "ADD COLUMN CancelledAt DATETIME NULL" },
      { name: 'CancelledBy', sql: "ADD COLUMN CancelledBy VARCHAR(50) NULL" }
    ];

    for (const col of columnsToAdd) {
      try {
        await connection.query(`ALTER TABLE PRY_Acceso ${col.sql}`);
        console.log(`  - Added ${col.name}`);
      } catch (err) {
        if (err.code === 'ER_DUP_FIELDNAME') {
          console.log(`  - ${col.name} already exists`);
        } else {
          console.log(`  - Warning: ${col.name}: ${err.message.substring(0, 50)}`);
        }
      }
    }

    // Create PRY_Invitacion table
    console.log('\nStep 2: Creating PRY_Invitacion table...');
    await connection.query(`
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
        FechaCreacion DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('  - PRY_Invitacion created/exists');
    try {
      await connection.query("ALTER TABLE PRY_Invitacion ADD COLUMN TipoInvitacion VARCHAR(50) DEFAULT 'Visitante' AFTER TelefonoInvitado");
      console.log('  - PRY_Invitacion.TipoInvitacion added');
    } catch (e) {
      if (e.code === 'ER_DUP_FIELDNAME') console.log('  - TipoInvitacion already exists');
      else console.log('  - TipoInvitacion:', e.message.substring(0, 50));
    }

    // Create PRY_AccessEvent table
    console.log('\nStep 3: Creating PRY_AccessEvent table...');
    await connection.query(`
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
        Activo TINYINT(1) DEFAULT 1
      )
    `);
    console.log('  - PRY_AccessEvent created/exists');

    // Create stored procedures
    console.log('\nStep 4: Creating stored procedures...');

    const procedures = [
      {
        name: 'spPRY_Invitacion_Crear',
        sql: `CREATE PROCEDURE spPRY_Invitacion_Crear(
          IN p_IDAcceso VARCHAR(50), IN p_CreadoPor VARCHAR(50), IN p_NombreInvitado VARCHAR(255),
          IN p_RutInvitado VARCHAR(50), IN p_CorreoInvitado VARCHAR(255), IN p_TelefonoInvitado VARCHAR(20),
          IN p_TipoInvitacion VARCHAR(50), IN p_Motivo VARCHAR(500), IN p_FechaInicio DATETIME, IN p_FechaFin DATETIME,
          IN p_IDSala INT, IN p_UsageLimit INT, IN p_QRCode TEXT
        ) BEGIN
          INSERT INTO PRY_Invitacion (IDAcceso, CreadoPor, NombreInvitado, RutInvitado, CorreoInvitado,
            TelefonoInvitado, TipoInvitacion, Motivo, FechaInicio, FechaFin, IDSala, UsageLimit, QRCode)
          VALUES (p_IDAcceso, p_CreadoPor, p_NombreInvitado, p_RutInvitado, p_CorreoInvitado,
            p_TelefonoInvitado, COALESCE(p_TipoInvitacion, 'Visitante'), p_Motivo, p_FechaInicio, p_FechaFin, p_IDSala, p_UsageLimit, p_QRCode);
          SELECT LAST_INSERT_ID() AS IDInvitacion;
        END`
      },
      {
        name: 'spPRY_Invitacion_Listar',
        sql: `CREATE PROCEDURE spPRY_Invitacion_Listar(IN p_CreadoPor VARCHAR(50)) BEGIN
          SELECT i.IDInvitacion, i.IDAcceso, i.NombreInvitado, i.RutInvitado, i.CorreoInvitado,
            i.TelefonoInvitado, i.TipoInvitacion, i.Motivo, i.FechaInicio, i.FechaFin, i.IDSala, s.Sala,
            i.Status, i.UsageLimit, i.UsedCount, i.QRCode, i.FechaCreacion, i.CancelledAt,
            CASE WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
              WHEN i.Status = 'USED' THEN 'USED'
              WHEN NOW() > i.FechaFin THEN 'EXPIRED'
              WHEN NOW() < i.FechaInicio THEN 'PENDING'
              ELSE 'ACTIVE' END AS StatusActual
          FROM PRY_Invitacion i LEFT JOIN PRY_Sala s ON i.IDSala = s.IDSala
          WHERE i.CreadoPor = p_CreadoPor AND i.Activo = 1 ORDER BY i.FechaCreacion DESC;
        END`
      },
      {
        name: 'spPRY_Invitacion_Obtener',
        sql: `CREATE PROCEDURE spPRY_Invitacion_Obtener(IN p_IDInvitacion INT) BEGIN
          SELECT i.*, s.Sala,
            CASE WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
              WHEN i.Status = 'USED' THEN 'USED'
              WHEN NOW() > i.FechaFin THEN 'EXPIRED'
              WHEN NOW() < i.FechaInicio THEN 'PENDING'
              ELSE 'ACTIVE' END AS StatusActual
          FROM PRY_Invitacion i LEFT JOIN PRY_Sala s ON i.IDSala = s.IDSala
          WHERE i.IDInvitacion = p_IDInvitacion AND i.Activo = 1;
        END`
      },
      {
        name: 'spPRY_Invitacion_Cancelar',
        sql: `CREATE PROCEDURE spPRY_Invitacion_Cancelar(IN p_IDInvitacion INT, IN p_CancelledBy VARCHAR(50)) BEGIN
          DECLARE v_IDAcceso VARCHAR(50);
          SELECT IDAcceso INTO v_IDAcceso FROM PRY_Invitacion WHERE IDInvitacion = p_IDInvitacion;
          UPDATE PRY_Invitacion SET Status = 'CANCELLED', CancelledAt = NOW(), CancelledBy = p_CancelledBy
            WHERE IDInvitacion = p_IDInvitacion;
          UPDATE PRY_Acceso SET Status = 'CANCELLED', Activo = 0, CancelledAt = NOW(), CancelledBy = p_CancelledBy
            WHERE IDAcceso = v_IDAcceso;
          SELECT ROW_COUNT() AS affected;
        END`
      },
      {
        name: 'spPRY_Invitacion_Validar',
        sql: `CREATE PROCEDURE spPRY_Invitacion_Validar(IN p_IDAcceso VARCHAR(50)) BEGIN
          SELECT i.IDInvitacion, i.IDAcceso, i.NombreInvitado, i.FechaInicio, i.FechaFin,
            i.IDSala, i.Status, i.UsageLimit, i.UsedCount,
            CASE WHEN i.Status = 'CANCELLED' THEN 'CANCELLED'
              WHEN i.Status = 'USED' THEN 'USED'
              WHEN i.UsedCount >= i.UsageLimit THEN 'USED'
              WHEN NOW() > i.FechaFin THEN 'EXPIRED'
              WHEN NOW() < i.FechaInicio THEN 'NOT_YET_VALID'
              ELSE 'VALID' END AS ValidationResult
          FROM PRY_Invitacion i WHERE i.IDAcceso = p_IDAcceso AND i.Activo = 1;
        END`
      },
      {
        name: 'spPRY_Invitacion_MarcarUsada',
        sql: `CREATE PROCEDURE spPRY_Invitacion_MarcarUsada(IN p_IDAcceso VARCHAR(50)) BEGIN
          UPDATE PRY_Invitacion SET UsedCount = UsedCount + 1,
            Status = CASE WHEN UsedCount + 1 >= UsageLimit THEN 'USED' ELSE Status END
          WHERE IDAcceso = p_IDAcceso AND Activo = 1;
          UPDATE PRY_Acceso SET UsedCount = UsedCount + 1,
            Status = CASE WHEN UsedCount + 1 >= UsageLimit THEN 'USED' ELSE Status END
          WHERE IDAcceso = p_IDAcceso;
        END`
      },
      {
        name: 'spPRY_AccessEvent_Registrar',
        sql: `CREATE PROCEDURE spPRY_AccessEvent_Registrar(
          IN p_IDAcceso VARCHAR(50), IN p_IDInvitacion INT, IN p_DeviceSN VARCHAR(100),
          IN p_DeviceName VARCHAR(255), IN p_Puerta VARCHAR(100),
          IN p_Result ENUM('ALLOWED', 'DENIED'), IN p_Reason VARCHAR(100), IN p_RawData TEXT
        ) BEGIN
          INSERT INTO PRY_AccessEvent (IDAcceso, IDInvitacion, DeviceSN, DeviceName, Puerta, Result, Reason, RawData)
          VALUES (p_IDAcceso, p_IDInvitacion, p_DeviceSN, p_DeviceName, p_Puerta, p_Result, p_Reason, p_RawData);
          SELECT LAST_INSERT_ID() AS IDEvent;
        END`
      },
      {
        name: 'spPRY_AccessEvent_Listar',
        sql: `CREATE PROCEDURE spPRY_AccessEvent_Listar(IN p_IDInvitacion INT) BEGIN
          SELECT * FROM PRY_AccessEvent WHERE IDInvitacion = p_IDInvitacion ORDER BY ScannedAt DESC;
        END`
      }
    ];

    for (const proc of procedures) {
      try {
        await connection.query(`DROP PROCEDURE IF EXISTS ${proc.name}`);
        await connection.query(proc.sql);
        console.log(`  - ${proc.name} created`);
      } catch (err) {
        console.log(`  - Warning: ${proc.name}: ${err.message.substring(0, 50)}`);
      }
    }

    // Create indexes
    console.log('\nStep 5: Creating indexes...');
    const indexes = [
      { name: 'idx_invitacion_creador', table: 'PRY_Invitacion', column: 'CreadoPor' },
      { name: 'idx_invitacion_status', table: 'PRY_Invitacion', column: 'Status' },
      { name: 'idx_invitacion_acceso', table: 'PRY_Invitacion', column: 'IDAcceso' },
      { name: 'idx_event_acceso', table: 'PRY_AccessEvent', column: 'IDAcceso' },
      { name: 'idx_event_fecha', table: 'PRY_AccessEvent', column: 'ScannedAt' },
      { name: 'idx_event_result', table: 'PRY_AccessEvent', column: 'Result' },
      { name: 'idx_acceso_status', table: 'PRY_Acceso', column: 'Status' }
    ];

    for (const idx of indexes) {
      try {
        await connection.query(`CREATE INDEX ${idx.name} ON ${idx.table}(${idx.column})`);
        console.log(`  - ${idx.name} created`);
      } catch (err) {
        if (err.code === 'ER_DUP_KEYNAME') {
          console.log(`  - ${idx.name} already exists`);
        } else {
          console.log(`  - Warning: ${idx.name}: ${err.message.substring(0, 40)}`);
        }
      }
    }

    console.log('\n========================================');
    console.log('  Migration Complete!');
    console.log('========================================\n');

  } catch (error) {
    console.error('\nMigration failed:', error.message);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

runMigration();
