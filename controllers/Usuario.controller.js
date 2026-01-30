const { findMany, pool, findOne } = require("../database/database")
const { getRandomNumericString } = require("../utils/Functions")
const { sendMail } = require("./mail.controller")

const getUsers = async (_, res) => {
  try {
    const data = await findMany('call spPRY_Usuario_Listar();', [])
    const usuarios = data.map(({ IDUsuario, NombreUsuario, CorreoElectronico, Telefono, IDRol, Rol, IDAcceso }) => ({
      idUsuario: IDUsuario,
      nombreUsuario: NombreUsuario,
      correoElectronico: CorreoElectronico,
      telefono: Telefono,
      idRol: IDRol,
      rol: Rol,
      idAcceso: IDAcceso
    }))
    return res.status(200).json(usuarios)
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

const getRolesSelect = async (req, res) => {
  try {
    const { idUsuario } = req.params
    const data = await findMany('call spPRY_Rol_Select(?);', [idUsuario])
    const usuarios = data.map(({ Restriccion, Descripcion }) => ({
      value: Restriccion,
      label: Descripcion
    }))
    return res.status(200).json(usuarios)
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

const postData = async (req, res) => {
  try {
    const { rut, nombre, correo, telefono, passwd, idRol } = req.body

    await pool.query('call spPRY_Usuario_Guardar(?,?,?,?,?,?,?,?,?);', [rut, nombre, passwd, correo, telefono, idRol, null, null, null])

    const mailOptions = {
      from: `"Control De Acceso" <${process.env.EMAIL_USER}>`,
      to: `${correo}`,
      subject: `Registro en aplicación`,
      html: `
          <h3>Nueva Información de Contacto</h3>
          <p><strong>Usuario:</strong> ${rut}</p>
          <p><strong>Contraseña temporal:</strong> ${passwd}</p>
      `
    };

    await sendMail(mailOptions);

    const data = await findMany('call spPRY_Usuario_Listar();', [])
    const usuarios = data.map(({ IDUsuario, NombreUsuario, CorreoElectronico, Telefono, IDRol, Rol, IDAcceso }) => ({
      idUsuario: IDUsuario,
      nombreUsuario: NombreUsuario,
      correoElectronico: CorreoElectronico,
      telefono: Telefono,
      idRol: IDRol,
      rol: Rol,
      idAcceso: IDAcceso
    }))
    return res.status(200).json({ message: "Usuario agregado exitosamente.", data: usuarios })
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

const postEnlace = async (req, res) => {
  try {
    const { rut, fechaInicio, fechaFin, sala } = req.body
    let { codigo } = req.body

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
      sala,
      isCard: true
    }

    await pool.query('call spPRY_Usuario_AgregarEnlace(?,?,?);', [codigo, rut, JSON.stringify(payload)])

    return res.status(200).json({ message: "Usuario enlazado exitosamente." })
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

const getEnlace = async (req, res) => {
  try {
    const { idUsuario } = req.params
    const data = await findOne('call spPRY_Usuario_Enlace_Listar(?);', [idUsuario])
    const payload = JSON.parse(data.Payload)
    const acceso = {
      idAcceso: data.IDAcceso,
      idUsuario: data.IDUsuario,
      fechaInicio: payload.fechaInicio,
      fechaFin: payload.fechaFin,
      idSala: payload.sala,
    }
    return res.status(200).json(acceso)
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}


const deleteData = async (req, res) => {
  try {
    const { idUsuario } = req.params

    await pool.query('call spPRY_Usuario_Eliminar(?);', [idUsuario])

    const data = await findMany('call spPRY_Usuario_Listar();', [])
    const usuarios = data.map(({ IDUsuario, NombreUsuario, CorreoElectronico, Telefono, IDRol, Rol, IDAcceso }) => ({
      idUsuario: IDUsuario,
      nombreUsuario: NombreUsuario,
      correoElectronico: CorreoElectronico,
      telefono: Telefono,
      idRol: IDRol,
      rol: Rol,
      idAcceso: IDAcceso
    }))
    return res.status(200).json({ message: "Usuario eliminado exitosamente.", data: usuarios })
  } catch ({ message }) {
    return res.status(403).json({ message })
  }
}

module.exports = {
  getUsers,
  getRolesSelect,
  deleteData,
  postData,
  postEnlace,
  getEnlace
}