const qr = require("qr-image");
const { pool, findOne, findMany } = require("../database/database");
const { sendMail } = require("./mail.controller");
const { getRandomNumericString } = require("../utils/Functions");

/**
 * Create a new invitation
 * POST /invitations
 */
const createInvitation = async (req, res) => {
  console.log('[Invitation] Creating invitation...');
  console.log('[Invitation] Body:', JSON.stringify(req.body));

  try {
    const {
      createdBy,
      nombreInvitado,
      rutInvitado,
      correoInvitado,
      telefonoInvitado,
      motivo,
      fechaInicio,
      fechaFin,
      idSala,
      usageLimit = 1
    } = req.body;

    // Validate required fields
    if (!createdBy || !nombreInvitado || !fechaInicio || !fechaFin) {
      return res.status(400).json({ 
        success: false, 
        message: 'Campos requeridos: createdBy, nombreInvitado, fechaInicio, fechaFin' 
      });
    }

    // Generate unique access code
    const existingIds = await findMany("call spPRY_IDAcceso_Listar();", []);
    let codigo;
    do {
      codigo = getRandomNumericString(10);
    } while (existingIds.some(item => item["IDAcceso"] === codigo));

    // Generate QR code
    const qrImage = qr.imageSync(codigo, { type: 'png' });
    const qrBase64 = `data:image/png;base64,${qrImage.toString("base64")}`;

    // Create access record
    const payload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala: idSala,
      isCard: false,
      isVisit: true
    };

    await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [
      codigo, 
      rutInvitado || createdBy, 
      JSON.stringify(payload)
    ]);

    // Create invitation record
    const [result] = await pool.query(
      'call spPRY_Invitacion_Crear(?,?,?,?,?,?,?,?,?,?,?,?);',
      [
        codigo, createdBy, nombreInvitado, rutInvitado, correoInvitado,
        telefonoInvitado, motivo, fechaInicio, fechaFin, idSala, usageLimit, qrBase64
      ]
    );

    const invitationId = result[0]?.[0]?.IDInvitacion;

    // Send email with QR if email provided
    if (correoInvitado) {
      try {
        const mailOptions = {
          from: `"Control De Acceso" <${process.env.EMAIL_USER}>`,
          to: correoInvitado,
          subject: 'Invitación de Acceso',
          html: `
            <h2>Invitación de Acceso</h2>
            <p>Hola <strong>${nombreInvitado}</strong>,</p>
            <p>Has recibido una invitación de acceso.</p>
            <p><strong>Válido desde:</strong> ${fechaInicio}</p>
            <p><strong>Válido hasta:</strong> ${fechaFin}</p>
            ${motivo ? `<p><strong>Motivo:</strong> ${motivo}</p>` : ''}
            <p>Presenta el código QR adjunto en la entrada.</p>
          `,
          attachments: [{
            filename: 'qr-acceso.png',
            content: Buffer.from(qrBase64.replace(/^data:image\/\w+;base64,/, ""), 'base64'),
            encoding: 'base64'
          }]
        };
        await sendMail(mailOptions);
        console.log('[Invitation] Email sent to:', correoInvitado);
      } catch (emailErr) {
        console.error('[Invitation] Email error:', emailErr.message);
      }
    }

    console.log('[Invitation] Created successfully:', invitationId);

    return res.status(201).json({
      success: true,
      message: 'Invitación creada exitosamente',
      data: {
        idInvitacion: invitationId,
        idAcceso: codigo,
        qrCode: qrBase64,
        fechaInicio,
        fechaFin,
        status: 'ACTIVE'
      }
    });

  } catch (error) {
    console.error('[Invitation] Error creating:', error);
    return res.status(500).json({ 
      success: false, 
      message: error.message || 'Error al crear invitación' 
    });
  }
};

/**
 * List invitations for a user
 * GET /invitations?userId=xxx
 */
const listInvitations = async (req, res) => {
  console.log('[Invitation] Listing invitations...');

  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId es requerido' 
      });
    }

    // Normalize userId (remove dots from RUT)
    const normalizedUserId = userId.replace(/\./g, '');

    const invitations = await findMany('call spPRY_Invitacion_Listar(?);', [normalizedUserId]);

    const formattedInvitations = (invitations || []).map(inv => ({
      id: inv.IDInvitacion,
      idAcceso: inv.IDAcceso,
      nombreInvitado: inv.NombreInvitado,
      rutInvitado: inv.RutInvitado,
      correoInvitado: inv.CorreoInvitado,
      telefonoInvitado: inv.TelefonoInvitado,
      motivo: inv.Motivo,
      fechaInicio: inv.FechaInicio,
      fechaFin: inv.FechaFin,
      idSala: inv.IDSala,
      sala: inv.Sala,
      status: inv.StatusActual,
      usageLimit: inv.UsageLimit,
      usedCount: inv.UsedCount,
      qrCode: inv.QRCode,
      fechaCreacion: inv.FechaCreacion,
      cancelledAt: inv.CancelledAt
    }));

    console.log('[Invitation] Found:', formattedInvitations.length);

    return res.status(200).json({
      success: true,
      data: formattedInvitations
    });

  } catch (error) {
    console.error('[Invitation] Error listing:', error);
    return res.status(500).json({ 
      success: false, 
      message: error.message || 'Error al listar invitaciones' 
    });
  }
};

/**
 * Get single invitation
 * GET /invitations/:id
 */
const getInvitation = async (req, res) => {
  console.log('[Invitation] Getting invitation:', req.params.id);

  try {
    const { id } = req.params;

    const invitation = await findOne('call spPRY_Invitacion_Obtener(?);', [id]);

    if (!invitation) {
      return res.status(404).json({ 
        success: false, 
        message: 'Invitación no encontrada' 
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        id: invitation.IDInvitacion,
        idAcceso: invitation.IDAcceso,
        nombreInvitado: invitation.NombreInvitado,
        rutInvitado: invitation.RutInvitado,
        correoInvitado: invitation.CorreoInvitado,
        telefonoInvitado: invitation.TelefonoInvitado,
        motivo: invitation.Motivo,
        fechaInicio: invitation.FechaInicio,
        fechaFin: invitation.FechaFin,
        idSala: invitation.IDSala,
        sala: invitation.Sala,
        status: invitation.StatusActual,
        usageLimit: invitation.UsageLimit,
        usedCount: invitation.UsedCount,
        qrCode: invitation.QRCode,
        fechaCreacion: invitation.FechaCreacion,
        cancelledAt: invitation.CancelledAt
      }
    });

  } catch (error) {
    console.error('[Invitation] Error getting:', error);
    return res.status(500).json({ 
      success: false, 
      message: error.message || 'Error al obtener invitación' 
    });
  }
};

/**
 * Cancel an invitation
 * POST /invitations/:id/cancel
 */
const cancelInvitation = async (req, res) => {
  console.log('[Invitation] Cancelling invitation:', req.params.id);

  try {
    const { id } = req.params;
    const { cancelledBy } = req.body;

    if (!cancelledBy) {
      return res.status(400).json({ 
        success: false, 
        message: 'cancelledBy es requerido' 
      });
    }

    // Normalize cancelledBy (remove dots from RUT)
    const normalizedCancelledBy = cancelledBy.replace(/\./g, '');

    // Check invitation exists
    const invitation = await findOne('call spPRY_Invitacion_Obtener(?);', [id]);
    
    if (!invitation) {
      return res.status(404).json({ 
        success: false, 
        message: 'Invitación no encontrada' 
      });
    }

    if (invitation.Status === 'CANCELLED') {
      return res.status(400).json({ 
        success: false, 
        message: 'La invitación ya está cancelada' 
      });
    }

    // Cancel the invitation
    await pool.query('call spPRY_Invitacion_Cancelar(?,?);', [id, normalizedCancelledBy]);

    console.log('[Invitation] Cancelled successfully');

    return res.status(200).json({
      success: true,
      message: 'Invitación cancelada exitosamente'
    });

  } catch (error) {
    console.error('[Invitation] Error cancelling:', error);
    return res.status(500).json({ 
      success: false, 
      message: error.message || 'Error al cancelar invitación' 
    });
  }
};

/**
 * Validate QR code for access (both invitation and personal QR codes)
 * POST /access/validate-qr
 */
const validateQR = async (req, res) => {
  console.log('[Access] Validating QR...');
  console.log('[Access] Body:', JSON.stringify(req.body));

  try {
    const { qrCode, deviceId, deviceName, puerta } = req.body;

    if (!qrCode) {
      return res.status(400).json({ 
        allowed: false, 
        reason: 'QR code is required' 
      });
    }

    let result = 'DENIED';
    let reason = 'INVALID';
    let allowed = false;
    let invitation = null;
    let personalAccess = null;
    let userName = null;
    let validUntil = null;
    let qrType = null; // 'invitation' or 'personal'

    // First, try to validate as invitation QR code
    invitation = await findOne('call spPRY_Invitacion_Validar(?);', [qrCode]);

    if (invitation) {
      // This is an invitation QR code
      qrType = 'invitation';
      const validationResult = invitation.ValidationResult;
      
      switch (validationResult) {
        case 'VALID':
          result = 'ALLOWED';
          reason = 'ACCESS_GRANTED';
          allowed = true;
          userName = invitation.NombreInvitado;
          validUntil = invitation.FechaFin;
          // Mark as used
          await pool.query('call spPRY_Invitacion_MarcarUsada(?);', [qrCode]);
          console.log('[Access] Invitation QR validated successfully');
          break;
        case 'CANCELLED':
          reason = 'INVITATION_CANCELLED';
          break;
        case 'USED':
          reason = 'USAGE_LIMIT_REACHED';
          break;
        case 'EXPIRED':
          reason = 'INVITATION_EXPIRED';
          break;
        case 'NOT_YET_VALID':
          reason = 'NOT_YET_VALID';
          break;
        default:
          reason = 'UNKNOWN_ERROR';
      }
    } else {
      // Not an invitation, try to validate as personal QR code
      qrType = 'personal';
      personalAccess = await findOne('call spPRY_Acceso_ObtenerPorAcceso(?);', [qrCode]);
      
      if (personalAccess && personalAccess.Payload) {
        try {
          const payload = JSON.parse(personalAccess.Payload);
          const now = new Date();
          const tokenStart = new Date(payload.fechaInicio);
          const tokenEnd = new Date(payload.fechaFin);

          console.log('[Access] Personal QR found. Validating token and lease...');
          console.log('[Access] Now:', now);
          console.log('[Access] Token valid:', tokenStart, '-', tokenEnd);

          // 1. Short-lived token must be valid
          if (now < tokenStart) {
            reason = 'NOT_YET_VALID';
            console.log('[Access] Personal QR token not yet valid');
          } else if (now > tokenEnd) {
            reason = 'EXPIRED';
            console.log('[Access] Personal QR token expired');
          } else {
            // 2. For Residente (3) and Personal (4), also check lease/contract period when present
            const roleId = payload.roleId ?? 1;
            if (roleId === 3 || roleId === 4) {
              const leaseStart = payload.leaseStart ? new Date(payload.leaseStart) : null;
              const leaseEnd = payload.leaseEnd ? new Date(payload.leaseEnd) : null;
              if (leaseStart && leaseEnd && (now < leaseStart || now > leaseEnd)) {
                reason = 'OUTSIDE_ACCESS_PERIOD';
                console.log('[Access] User access period (Inicio/Fin) does not include now');
              } else {
                result = 'ALLOWED';
                reason = 'ACCESS_GRANTED';
                allowed = true;
                userName = personalAccess.NombreUsuario || personalAccess.IDUsuario;
                validUntil = payload.fechaFin;
                console.log('[Access] Personal QR validated for user:', userName);
              }
            } else {
              result = 'ALLOWED';
              reason = 'ACCESS_GRANTED';
              allowed = true;
              userName = personalAccess.NombreUsuario || personalAccess.IDUsuario;
              validUntil = payload.fechaFin;
              console.log('[Access] Personal QR validated for user:', userName);
            }
          }
        } catch (parseErr) {
          console.error('[Access] Error parsing payload:', parseErr);
          reason = 'INVALID_PAYLOAD';
        }
      } else {
        reason = 'INVALID_CODE';
        console.log('[Access] QR code not found in database');
      }
    }

    // Log the access event
    try {
      await pool.query('call spPRY_AccessEvent_Registrar(?,?,?,?,?,?,?,?);', [
        qrCode,
        invitation?.IDInvitacion || null,
        deviceId || null,
        deviceName || null,
        puerta || null,
        result,
        reason,
        JSON.stringify(req.body)
      ]);
    } catch (logErr) {
      console.error('[Access] Error logging event:', logErr.message);
    }

    console.log('[Access] Result:', { allowed, reason, qrType, userName });

    return res.status(200).json({
      allowed,
      reason,
      action: allowed ? 'OPEN_DOOR' : null,
      qrType: qrType || 'unknown',
      user: allowed ? {
        nombre: userName,
        validUntil: validUntil
      } : null
    });

  } catch (error) {
    console.error('[Access] Error validating:', error);
    return res.status(500).json({ 
      allowed: false, 
      reason: 'SERVER_ERROR' 
    });
  }
};

/**
 * Get access events for an invitation
 * GET /invitations/:id/events
 */
const getInvitationEvents = async (req, res) => {
  console.log('[Invitation] Getting events for:', req.params.id);

  try {
    const { id } = req.params;

    const events = await findMany('call spPRY_AccessEvent_Listar(?);', [id]);

    return res.status(200).json({
      success: true,
      data: (events || []).map(e => ({
        id: e.IDEvent,
        scannedAt: e.ScannedAt,
        result: e.Result,
        reason: e.Reason,
        deviceSN: e.DeviceSN,
        deviceName: e.DeviceName,
        puerta: e.Puerta
      }))
    });

  } catch (error) {
    console.error('[Invitation] Error getting events:', error);
    return res.status(500).json({ 
      success: false, 
      message: error.message || 'Error al obtener eventos' 
    });
  }
};

module.exports = {
  createInvitation,
  listInvitations,
  getInvitation,
  cancelInvitation,
  validateQR,
  getInvitationEvents
};
