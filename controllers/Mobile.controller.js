const qr = require("qr-image");
const Cryptojs = require("crypto-js")
const { exists, pool, findOne, findMany } = require("../database/database");
const { sendMail } = require("./mail.controller");
const { Buffer } = require("buffer");
const { getRandomNumericString } = require("../utils/Functions");

const obtainQR = async (req, res) => {
  try {
    const { user, fechaInicio, fechaFin } = req.body;
    console.log('[ObtainQR] Request for user:', user);
    
    // Get existing access record for user
    let datos = null;
    let payload = null;
    
    try {
      datos = await findOne('call spPRY_Acceso_ObtenerPorUsuario(?);', [user]);
      if (datos && datos.Payload) {
        payload = JSON.parse(datos.Payload);
      }
    } catch (e) {
      console.log('[ObtainQR] No existing access record found for user:', user);
    }
    
    // Generate a unique code for the QR
    const ids = await findMany("call spPRY_IDAcceso_Listar();", []);
    let codigo;
    do {
      codigo = getRandomNumericString(10);
    } while (ids.some(item => item["IDAcceso"] === codigo));
    
    console.log('[ObtainQR] Generated code:', codigo);
    
    // Create new payload with fresh timestamps
    const newPayload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala: payload?.sala || null,
      isCard: false
    };
    
    // Save/update the access record
    try {
      await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, user, JSON.stringify(newPayload)]);
      console.log('[ObtainQR] Access record saved');
    } catch (e) {
      console.log('[ObtainQR] Error saving access record:', e.message);
      // Continue anyway - we can still generate QR
    }

    // Generate QR code image
    const qrImage = qr.imageSync(`${codigo}`, { type: 'png' });
    const base64 = qrImage.toString("base64");
    
    console.log('[ObtainQR] QR generated successfully');
    res.status(200).json({ qrCode: `data:image/png;base64,${base64}` });
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

const addUsuario = async (req, res) => {
  try {
    const { rut, nombre, correo, telefono, rol, fechaInicio, fechaFin, sala } = req.body;

    const existe = await exists('tbl_usuarios', `IDUsuario = "${rut}"`);

    if (existe)
      throw new Error("Usuario ya existe.");

    const pass = getRandomString(8);

    await pool.query('call spPRY_Usuario_Guardar(?,?,?,?,?,?);',
      [rut, nombre, pass, correo, telefono, rol])

    const ids = await findMany("call spPRY_IDAcceso_Listar();", []);

    let codigo = "";

    do {
      codigo = getRandomNumericString(10)
    } while (ids.some(item => item["IDAcceso"] === codigo));

    const payload = {
      codigo,
      fechaInicio,
      fechaFin,
      sala,
      isCard: false
    }

    await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, rut, JSON.stringify(payload)])

    const mailOptions = {
      from: `"Control De Acceso" <${process.env.EMAIL_USER}>`,
      to: `${correo}`,
      subject: `Registro en aplicación`,
      html: `
          <h3>Nueva Información de Contacto</h3>
          <p><strong>Usuario:</strong> ${rut}</p>
          <p><strong>Contraseña temporal:</strong> ${pass}</p>
      `
    };

    await sendMail(mailOptions);

    res.status(200).json({ message: 'Usuario creado correctamente' })
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

const login = async (req, res) => {
  console.log('[Mobile Login] ====== Login Request ======');
  console.log('[Mobile Login] Body:', JSON.stringify(req.body));
  
  const { username: rawUsername, password } = req.body
  // Remove dots from RUT for database lookup (e.g., "11.111.111-1" -> "11111111-1")
  const username = rawUsername ? rawUsername.replace(/\./g, '') : '';
  
  console.log('[Mobile Login] Raw Username:', rawUsername);
  console.log('[Mobile Login] Normalized Username:', username);
  console.log('[Mobile Login] Password received:', password ? '***' : 'EMPTY');
  
  try {
    console.log('[Mobile Login] Querying user from database...');
    const user = await findOne("call spPRY_Usuarios_ObtenerPorID(?)", [username])
    console.log('[Mobile Login] User found:', user ? 'YES' : 'NO');
    
    if (!user) {
      console.log('[Mobile Login] ERROR: User not found');
      throw new Error("Usuario inválido.")
    }
    
    console.log('[Mobile Login] User data:', JSON.stringify({
      IDUsuario: user.IDUsuario,
      NombreUsuario: user.NombreUsuario,
      IDRol: user.IDRol,
      PassTemp: user.PassTemp
    }));
    
    const hashedInput = String(Cryptojs.MD5(password));
    console.log('[Mobile Login] Password hash comparison:');
    console.log('[Mobile Login]   Input hash:', hashedInput);
    console.log('[Mobile Login]   DB hash:   ', user.Passwd);
    
    const isMatch = hashedInput === user.Passwd
    console.log('[Mobile Login] Password match:', isMatch);
    
    if (!isMatch) {
      console.log('[Mobile Login] ERROR: Password mismatch');
      throw new Error("Contraseña inválida.")
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

    // PassTemp is a number (0 or 1), not an array
    const passTemp = typeof user.PassTemp === 'number' ? user.PassTemp : (user.PassTemp?.[0] ?? 0);
    
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
  obtenerQR
}