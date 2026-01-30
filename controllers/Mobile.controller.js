const qr = require("qr-image");
const Cryptojs = require("crypto-js")
const { exists, pool, findOne, findMany } = require("../database/database");
const { sendMail } = require("./mail.controller");
const { Buffer } = require("buffer");
const { getRandomNumericString } = require("../utils/Functions");

const obtainQR = async (req, res) => {
  try {
    const { user } = req.body;
    if (!user) {
      return res.status(400).json({ message: 'user is required' });
    }
    const normalizedUser = (user || '').replace(/\./g, '').trim();
    console.log('[ObtainQR] Request for user:', normalizedUser);

    // Get user role for validity window: Admin = short-lived (2 min), others = 5 min
    const userRecord = await findOne('call spPRY_Usuarios_ObtenerPorID(?)', [normalizedUser]);
    const roleId = userRecord?.IDRol ?? 1;
    const validityMinutes = roleId === 1 ? 2 : 5; // Administrador: 2 min; Supervisor, Residente, Personal: 5 min

    const now = new Date();
    const end = new Date(now.getTime() + validityMinutes * 60 * 1000);
    const fechaInicio = now.toISOString().slice(0, 19).replace('T', ' ');
    const fechaFin = end.toISOString().slice(0, 19).replace('T', ' ');

    // Get existing access record to preserve lease (Tenant/Personal) and sala
    let payload = null;
    try {
      const datos = await findOne('call spPRY_Acceso_ObtenerPorUsuario(?);', [normalizedUser]);
      if (datos && datos.Payload) {
        payload = JSON.parse(datos.Payload);
      }
    } catch (e) {
      console.log('[ObtainQR] No existing access record found for user:', normalizedUser);
    }

    // Generate a unique code for the QR
    const ids = await findMany("call spPRY_IDAcceso_Listar();", []);
    let codigo;
    do {
      codigo = getRandomNumericString(10);
    } while (ids.some(item => item["IDAcceso"] === codigo));

    console.log('[ObtainQR] Generated code:', codigo, 'validity:', validityMinutes, 'min');

    // Lease from user record (single source of truth); fallback to payload for legacy
    const leaseStart = userRecord?.FechaInicioValidez ?? payload?.leaseStart ?? payload?.fechaInicio ?? null;
    const leaseEnd = userRecord?.FechaFinValidez ?? payload?.leaseEnd ?? payload?.fechaFin ?? null;
    const sala = userRecord?.IDSala ?? payload?.sala ?? null;

    const newPayload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala,
      isCard: false,
      roleId,
      leaseStart,
      leaseEnd
    };

    try {
      await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, normalizedUser, JSON.stringify(newPayload)]);
      console.log('[ObtainQR] Access record saved');
    } catch (e) {
      console.log('[ObtainQR] Error saving access record:', e.message);
    }

    const qrImage = qr.imageSync(`${codigo}`, { type: 'png' });
    const base64 = qrImage.toString("base64");

    res.status(200).json({
      qrCode: `data:image/png;base64,${base64}`,
      validityEnd: end.toISOString(),
      validityMinutes
    });
  } catch (err) {
    console.error('[ObtainQR] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
}

const obtenerQR = async (req, res) => {
  try {
    const { user } = req.params;
    const qrImage = qr.imageSync(`${user}`, { type: 'png' });
    const base64 = qrImage.toString("base64");
    res.status(200).json({ qrCode: `data:image/png;base64,${base64}` })
  } catch ({ message }) {
    return res.status(500).json({ message })
  }
}

const addVisita = async (req, res) => {
  try {
    const { rut, name, email, telefono, fechaInicio, fechaFin, nroUnidad } = req.body;

    let existe = await exists('tbl_usuarios', `IDUsuario = "${rut}"`);
    if (existe)
      throw new Error("Usuario ya existe.");

    existe = await exists('tbl_acceso', `IDUsuario = "${rut}"`);
    if (existe)
      throw new Error("Visita ya tiene acceso existe.");

    existe = await exists('tbl_visita', `IDVisita = "${rut}"`);
    if (existe) {
      await pool.query('call spPRY_Mobile_Visita_Actualizar(?,?,?,?,?,?,?);',
        [rut, name, email, telefono, fechaInicio, fechaFin, nroUnidad])
    } else {
      await pool.query('call spPRY_Mobile_Visita_Agregar(?,?,?,?,?,?,?);',
        [rut, name, email, telefono, fechaInicio, fechaFin, nroUnidad])
    }

    let codigo = ""
    const ids = await findMany("call spPRY_IDAcceso_Listar();", []);
    if (!codigo || codigo === "") {
      do {
        codigo = getRandomNumericString(10)
      } while (ids.some(item => item["IDAcceso"] === codigo));
    }

    const payload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala: nroUnidad,
      isCard: false,
      isVisit: true
    }

    await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, rut, JSON.stringify(payload)])

    const qrImage = qr.imageSync(`${codigo}`, { type: 'png' });
    const YOUR_BASE64_STRING = qrImage.toString("base64");

    const mailOptions = {
      from: `"Control De Acceso" <${process.env.EMAIL_USER}>`,
      to: `${email}`,
      subject: `Registro en aplicación`,
      text: "Use el QR adjunto para ingresar.",
      attachments: [
        {
          filename: 'image.png',
          content: Buffer.from(YOUR_BASE64_STRING.replace(/^data:image\/\w+;base64,/, ""), 'base64'),
          encoding: 'base64'
        }
      ]
    };

    await sendMail(mailOptions);

    res.status(200).json({ message: 'Invitación generada correctamente' })
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

// Check if RUT already exists
const checkRutExists = async (req, res) => {
  try {
    const { rut } = req.body;
    
    if (!rut || rut.trim() === '') {
      return res.status(400).json({ exists: false, message: 'RUT es requerido.' });
    }
    
    const normalizedRut = rut.replace(/\./g, '').trim();
    const existe = await exists('PRY_Usuarios', `IDUsuario = "${normalizedRut}"`);
    
    return res.status(200).json({ exists: existe });
  } catch (err) {
    return res.status(500).json({ exists: false, message: err.message });
  }
};

// Get user details by RUT or name for validation
const getUserByRut = async (req, res) => {
  try {
    const { rut } = req.body;
    
    if (!rut || rut.trim() === '') {
      return res.status(400).json({ success: false, message: 'RUT o nombre es requerido.' });
    }
    
    // First, try to find by RUT (IDUsuario)
    const normalizedRut = rut.replace(/\./g, '').trim();
    let user = await findOne("call spPRY_Usuarios_ObtenerPorID(?)", [normalizedRut]);
    
    // If not found by RUT, try to find by name (NombreUsuario)
    if (!user) {
      console.log('[GetUserByRut] User not found by RUT, trying to find by name:', rut.trim());
      user = await findOne(
        "SELECT IDUsuario, NombreUsuario, CorreoElectronico, Telefono, IDRol FROM PRY_Usuarios WHERE NombreUsuario = ? AND Activo = 1",
        [rut.trim()]
      );
    }
    
    if (!user) {
      return res.status(200).json({ success: true, exists: false, user: null });
    }
    
    return res.status(200).json({
      success: true,
      exists: true,
      user: {
        rut: user.IDUsuario,
        nombre: user.NombreUsuario,
        correo: user.CorreoElectronico,
        telefono: user.Telefono,
        idRol: user.IDRol
      }
    });
  } catch (err) {
    console.error('[GetUserByRut] Error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
};

// Get unidades (rooms) list
const getUnidades = async (req, res) => {
  try {
    console.log('[GetUnidades] Fetching unidades...');
    const _unidades = await findMany('call spPRY_Sala_Listar();', []);
    console.log('[GetUnidades] Raw unidades from DB:', JSON.stringify(_unidades));
    
    if (!_unidades || _unidades.length === 0) {
      console.warn('[GetUnidades] No unidades found in database');
      return res.status(200).json({ success: true, data: [] });
    }
    
    const unidades = _unidades.map((unidad) => ({
      value: unidad.IDSala,
      label: `${unidad.Edificio || ''}-${unidad.Piso || ''}${unidad.Sala || ''}`
    }));
    
    console.log('[GetUnidades] Formatted unidades:', JSON.stringify(unidades));
    return res.status(200).json({ success: true, data: unidades });
  } catch (err) {
    console.error('[GetUnidades] Error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
};

// Map frontend role codes to database role IDs (Administrador, Supervisor, Residente, Personal)
const mapRoleCodeToId = (roleCode) => {
  const roleMap = {
    'ADM': 1,  // Administrador
    'SUP': 2,  // Supervisor
    'RES': 3,  // Residente (Tenant)
    'PPL': 4,  // Personal (Staff)
    'SAD': 1,  // Super Admin -> Administrador
    // Legacy
    'OFC': 2,  'ENC': 2,  'USR': 3,  'PRO': 3,  'VIS': 4
  };
  
  if (typeof roleCode === 'number') return roleCode;
  if (!isNaN(roleCode)) return parseInt(roleCode, 10);
  
  const roleId = roleMap[roleCode?.toUpperCase()];
  if (!roleId) {
    throw new Error(`Rol inválido: ${roleCode}. Roles válidos: ADM, SUP, RES, PPL`);
  }
  return roleId;
};

const addUsuario = async (req, res) => {
  try {
    const { rut, nombre, correo, telefono, rol, fechaInicio, fechaFin, sala } = req.body;

    console.log('[AddUsuario] Request received:', { rut, nombre, correo, telefono, rol, sala });

    // Validate all required fields
    if (!rut || rut.trim() === '') {
      throw new Error("El RUT es requerido.");
    }
    
    if (!nombre || nombre.trim() === '') {
      throw new Error("El nombre completo es requerido.");
    }
    
    if (!correo || correo.trim() === '') {
      throw new Error("El correo electrónico es requerido.");
    }
    
    if (!telefono || telefono.trim() === '') {
      throw new Error("El teléfono es requerido.");
    }
    
    if (!rol) {
      throw new Error("El rol es requerido.");
    }

    // Unit (sala) is required only for Residente (role ID 3)
    const roleId = mapRoleCodeToId(rol);
    if (roleId === 3 && (!sala && sala !== 0)) {
      throw new Error("La unidad es requerida para el rol Residente.");
    }

    // Normalize RUT
    const normalizedRut = rut.replace(/\./g, '').trim();

    // Validate RUT format
    if (!normalizedRut.includes('-')) {
      throw new Error("Formato de RUT inválido. Debe incluir un guión (ej: 12345678-9).");
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(correo.trim())) {
      throw new Error("Formato de correo electrónico inválido.");
    }

    // Validate nombre format (min 3 chars, max 100, only letters/spaces)
    const trimmedNombre = nombre.trim();
    if (trimmedNombre.length < 3) {
      throw new Error("El nombre debe tener al menos 3 caracteres.");
    }
    if (trimmedNombre.length > 100) {
      throw new Error("El nombre no puede exceder 100 caracteres.");
    }
    const nombreRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s'-]+$/;
    if (!nombreRegex.test(trimmedNombre)) {
      throw new Error("El nombre solo puede contener letras, espacios y guiones.");
    }

    // Validate phone format (9 digits, starts with 9 or 2)
    const trimmedTelefono = telefono.trim();
    if (trimmedTelefono.length !== 9) {
      throw new Error("El teléfono debe tener 9 dígitos.");
    }
    if (!/^\d+$/.test(trimmedTelefono)) {
      throw new Error("El teléfono solo puede contener números.");
    }
    if (!/^[92]/.test(trimmedTelefono)) {
      throw new Error("El teléfono debe comenzar con 9 (móvil) o 2 (fijo).");
    }

    // Check if RUT already exists
    const existe = await exists('PRY_Usuarios', `IDUsuario = "${normalizedRut}"`);

    if (existe)
      throw new Error("El RUT ya está registrado.");

    console.log('[AddUsuario] Role code:', rol, '-> Role ID:', roleId);

    const pass = getRandomString(8);
    console.log('[AddUsuario] Generated password for user:', normalizedRut);

    const idSala = (roleId === 3 && sala) ? sala : null;
    const fechaInicioValidez = (roleId === 3 || roleId === 4) ? fechaInicio : null;
    const fechaFinValidez = (roleId === 3 || roleId === 4) ? fechaFin : null;

    console.log('[AddUsuario] Calling spPRY_Usuario_Guardar with:', {
      rut: normalizedRut,
      nombre: trimmedNombre,
      rolId: roleId,
      idSala: idSala,
      fechaInicioValidez,
      fechaFinValidez
    });

    await pool.query('call spPRY_Usuario_Guardar(?,?,?,?,?,?,?,?,?);', [
      normalizedRut, trimmedNombre, pass, correo.trim(), trimmedTelefono, roleId,
      idSala, fechaInicioValidez, fechaFinValidez
    ]);
    
    console.log('[AddUsuario] User saved successfully in PRY_Usuarios');

    const ids = await findMany("call spPRY_IDAcceso_Listar();", []);

    let codigo = "";

    do {
      codigo = getRandomNumericString(10)
    } while (ids.some(item => item["IDAcceso"] === codigo));

    const payload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala: sala || null,
      isCard: false,
      roleId,
      leaseStart: fechaInicio,
      leaseEnd: fechaFin
    }

    await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, normalizedRut, JSON.stringify(payload)])
    console.log('[AddUsuario] Access record created for user:', normalizedRut);

    // Send email with credentials
    try {
      const mailOptions = {
        from: `"Control De Acceso" <${process.env.EMAIL_USER}>`,
        to: `${correo}`,
        subject: `Registro en aplicación`,
        html: `
            <h3>Nueva Información de Contacto</h3>
            <p><strong>Usuario:</strong> ${normalizedRut}</p>
            <p><strong>Contraseña temporal:</strong> ${pass}</p>
        `
      };

      await sendMail(mailOptions);
      console.log('[AddUsuario] Email sent to:', correo);
    } catch (emailError) {
      console.error('[AddUsuario] Error sending email:', emailError.message);
      // Don't fail the request if email fails
    }

    console.log('[AddUsuario] User creation completed successfully');
    res.status(200).json({ message: 'Usuario creado correctamente' })
  } catch (err) {
    console.error('[AddUsuario] ERROR:', err.message);
    console.error('[AddUsuario] Full error:', err);
    return res.status(403).json({ message: err.message || 'Error al crear el usuario' })
  }
}

const login = async (req, res) => {
  console.log('[Mobile Login] ====== Login Request ======');
  console.log('[Mobile Login] Body:', JSON.stringify({ ...req.body, fullName: req.body.fullName ? '***' : '' }));
  
  const { username: rawUsername, fullName: rawFullName } = req.body;
  // Remove dots from RUT for database lookup (e.g., "11.111.111-1" -> "11111111-1")
  const username = rawUsername ? rawUsername.replace(/\./g, '') : '';
  const fullName = (rawFullName || '').trim();
  
  console.log('[Mobile Login] Raw Username:', rawUsername);
  console.log('[Mobile Login] Normalized Username:', username);
  console.log('[Mobile Login] Full name provided:', fullName ? 'YES' : 'NO');
  
  try {
    if (!fullName) {
      throw new Error("El nombre completo es requerido.");
    }

    console.log('[Mobile Login] Querying user from database...');
    const user = await findOne("call spPRY_Usuarios_ObtenerPorID(?)", [username]);
    console.log('[Mobile Login] User found:', user ? 'YES' : 'NO');
    
    if (!user) {
      console.log('[Mobile Login] ERROR: User not found');
      throw new Error("Usuario inválido.");
    }
    
    console.log('[Mobile Login] User data:', JSON.stringify({
      IDUsuario: user.IDUsuario,
      NombreUsuario: user.NombreUsuario,
      IDRol: user.IDRol
    }));
    
    // Validate full name matches (case-insensitive)
    const nameMatch = fullName.toLowerCase() === (user.NombreUsuario || '').toLowerCase();
    if (!nameMatch) {
      console.log('[Mobile Login] ERROR: Full name does not match');
      throw new Error("Nombre completo no coincide.");
    }

    console.log('[Mobile Login] Fetching roles...');
    const _roles = await findMany("call spPRY_Mobile_Rol_Select(?);", [username]);
    console.log('[Mobile Login] Roles raw data:', JSON.stringify(_roles));
    
    const roles = _roles.map((role) => ({
      value: role.value || role.IDRol || role.Restriccion,
      label: role.label || role.Descripcion,
      tipo: role.tipo || role.Tipo
    }))

    console.log('[Mobile Login] Fetching unidades...');
    const _unidades = await findMany('call spPRY_Sala_Listar();', []);
    console.log('[Mobile Login] Unidades raw data:', JSON.stringify(_unidades));
    
    const unidades = _unidades.map((unidad) => ({
      value: unidad.IDSala,
      label: `${unidad.Edificio || ''}-${unidad.Piso || ''}${unidad.Sala || ''}`
    }))

    // Name-based login: no password change flow (passTemp always 0)
    const passTemp = 0;
    
    const responseData = { 
      username: user.NombreUsuario, 
      user: username, 
      userrol: user.IDRol, 
      passTemp: passTemp, 
      roles, 
      unidades 
    };
    console.log('[Mobile Login] SUCCESS - Sending response:', JSON.stringify(responseData));
    
    return res.json(responseData)
  } catch (err) {
    console.log('[Mobile Login] CATCH ERROR:', err.message);
    console.log('[Mobile Login] Full error:', err);
    const { message } = err
    return res.status(403).json({ message })
  }
}

function getRandomString(length) {
  const buffer = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&@';
  let sb = '';
  const range = buffer.length;
  for (let i = 0; i < length; i++) {
    sb += buffer.charAt(Math.floor(Math.random() * range));
  }
  return sb;
}

module.exports = {
  obtainQR,
  addVisita,
  login,
  addUsuario,
  obtenerQR,
  checkRutExists,
  getUserByRut,
  getUnidades
}