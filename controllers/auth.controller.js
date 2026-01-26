const { findOne, pool } = require('../database/database.js')
const Cryptojs = require("crypto-js")

const login = async (req, res) => {
  const { username, password } = req.body
  console.log(username, password)
  try {
    const user = await findOne("call spPRY_Usuarios_ObtenerPorID(?)", [username])
    if (!user)
      throw new Error("Usuario inválido.")
    const isMatch = String(Cryptojs.MD5(password)) === user.Passwd
    if (!isMatch)
      throw new Error("Contraseña inválida.")

    return res.json({ username: user.NombreUsuario, user: username, userrol: user.IDRol, passTemp: user.PassTemp[0] })
  } catch (err) {
    const { message } = err
    return res.status(403).json({ message })
  }
}

const password = async (req, res) => {
  const { username, password } = req.body
  
  console.log('[Password] Change request for user:', username);
  
  try {
    // Validate required fields
    if (!username || !password) {
      throw new Error("Usuario y contraseña son requeridos.");
    }

    // Normalize username (remove dots from RUT)
    const normalizedUsername = username.replace(/\./g, '').trim();
    
    // Validate password length
    if (password.length < 6) {
      throw new Error("La contraseña debe tener al menos 6 caracteres.");
    }

    // First, try to find user by RUT (IDUsuario)
    let user = await findOne("call spPRY_Usuarios_ObtenerPorID(?)", [normalizedUsername])
    
    // If not found by RUT, try to find by name (NombreUsuario)
    if (!user) {
      console.log('[Password] User not found by RUT, trying to find by name:', username.trim());
      user = await findOne(
        "SELECT IDUsuario, NombreUsuario, Passwd, CorreoElectronico, Telefono, IDRol, PassTemp FROM PRY_Usuarios WHERE NombreUsuario = ? AND Activo = 1",
        [username.trim()]
      );
      
      if (user) {
        console.log('[Password] User found by name:', user.NombreUsuario, 'RUT:', user.IDUsuario);
      }
    }

    if (!user)
      throw new Error("Usuario no existe")

    const isMatch = String(Cryptojs.MD5(password)) === user.Passwd
    if (isMatch)
      throw new Error("Contraseña no puede ser igual a la anterior.")

    // Use the actual RUT (IDUsuario) from the user object
    const userRut = user.IDUsuario;
    await pool.query("call spPRY_Usuarios_CambiarPass(?,?)", [userRut, password])

    console.log('[Password] Password changed successfully for:', userRut, '(', user.NombreUsuario, ')');
    return res.json({ username: user.NombreUsuario, userrol: user.IDRol, passTemp: user.PassTemp })
  } catch (err) {
    console.error('[Password] Error:', err.message);
    const { message } = err
    return res.status(403).json({ message })
  }
}

module.exports = {
  login,
  password
}