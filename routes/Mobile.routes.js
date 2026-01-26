const { Router } = require('express')
const { obtainQR, addVisita, addUsuario, obtenerQR, login, checkRutExists, getUserByRut, getUnidades } = require('../controllers/Mobile.controller.js')
const router = Router()

router.post('/obtainQR', obtainQR)

router.post('/auth/login', login)

router.get('/obtainQR/:user', obtenerQR)

router.post('/visita', addVisita)

router.post('/registrar', addUsuario)
router.post('/createUser', addUsuario) // Alias for frontend compatibility

router.post('/check-rut', checkRutExists)
router.post('/get-user-by-rut', getUserByRut)
router.get('/unidades', getUnidades)

module.exports = { mobileRouter: router }