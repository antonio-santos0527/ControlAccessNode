require("dotenv").config()
const express = require('express')
const cors = require('cors')
const session = require('express-session')
const bodyParser = require('body-parser')
const fs = require('fs')
const listEndpoints = require('express-list-endpoints');
const { authRouter } = require("./routes/auth.routes.js")
const { empRouter } = require("./routes/Emp.routes.js")
const { dispositivoRouter } = require("./routes/Dispositivo.routes.js")
const { iclockRouter } = require("./routes/IClock.routes.js")
const { cmdRouter } = require('./routes/Cmd.routes.js');
const { realEventRouter } = require('./routes/RealEvent.routes.js');
const { timeRouter } = require('./routes/Time.routes.js');
const { createCmdRouter } = require('./routes/CreateCmd.routes.js');
const { authorityRouter } = require('./routes/Authority.routes.js');
const { deviceRouter } = require('./routes/Device.routes.js');
const { mobileRouter } = require('./routes/Mobile.routes.js');
const { edificioRouter } = require("./routes/Edificio.routes.js")
const { pisoRouter } = require('./routes/Piso.routes.js');
const { salaRouter } = require('./routes/Sala.routes.js');
const { ubicacionRouter } = require('./routes/Ubicacion.routes.js');
const { usuarioRouter } = require('./routes/Usuario.routes.js');
const { wsRouter } = require('./routes/ws.routes.js');
const stringify = require('json-stringify-safe');
const { addReqToLog } = require("./database/database.js")
const { client: whatsappClient } = require("./controllers/whatsapp.controller.js")
const { syncronizeRouter } = require("./routes/syncronize.routes.js")
const { invitationRouter } = require("./routes/Invitation.routes.js")
const { accessRouter } = require("./routes/Access.routes.js")
const app = express()

const whiteList = ['http://localhost:3000', 'http://zktecoprd.s3-website.us-east-2.amazonaws.com']

const corsOptions = {
  origin: function (origin, callback) {
    if (whiteList.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback('Not allow by CORS')
    }
  }
}

app.use(cors())
app.use(session({
  name: 'SessionCookie',
  secret: 'Shsh!Secret!',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Request Logger Middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`\n[${timestamp}] ========== Incoming Request ==========`);
  console.log(`[Request] ${req.method} ${req.originalUrl}`);
  console.log(`[Request] Content-Type: ${req.headers['content-type']}`);
  if (req.body && Object.keys(req.body).length > 0) {
    const safeBody = { ...req.body };
    if (safeBody.password) safeBody.password = '***';
    if (safeBody.fullName) safeBody.fullName = '***';
    console.log(`[Request] Body:`, JSON.stringify(safeBody));
  }
  next();
});

app.use((req, res, next) => {
  let parsedBody = req.body;
  let contentType = req.headers['content-type'] || "";
  if (contentType.startsWith('application/push')) {
    let body = "";
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      try {
        let path = req.originalUrl || "";
        if (path.includes("rtstate") || path.includes("rtlog")) {
          let params = body !== "" ? body.split("\t") : body;
          let obj = {};
          for (const param of params) {
            let s = param.split("=");
            if (s.length === 2)
              obj[s[0]] = s[1]
          }
          req.body = obj;
          parsedBody = obj;
        } else if (path.includes("devicecmd")) {
          req.body = body;
          parsedBody = body;
        } else {
          let params = body !== "" ? body.split(",") : body;
          let obj = {};
          for (const param of params) {
            let s = param.split("=");
            if (s.length === 2)
              obj[s[0]] = s[1]
          }
          req.body = obj;
          parsedBody = obj;
        }

        //OPCIONAL

        const requestDetails = `Solicitud recibida:
        Fecha: ${new Date().toISOString()}
        Método: ${req.method}
        URL: ${req.url}
        Pathname: ${req.path}
        Cabeceras: ${JSON.stringify(req.headers, null, 2)}
        Cuerpo: ${JSON.stringify(parsedBody, null, 2)}
        ------------------------------\n`;

        fs.appendFile('request.txt', requestDetails, (err) => {
          if (err) console.error('Error al guardar la solicitud en el archivo:', err)
        })

        //END OPCIONAL
        next()
      } catch (e) {
        console.log(e)
        res.status(400).send('Bad Request')
      }
    })
  } else {
    next()
  }
  // const { path } = req || ''
  // addReqToLog(path, 0, stringify(req))
  // next()
})

app.use("/auth", authRouter)
app.use(empRouter)
app.use(dispositivoRouter)
app.use(iclockRouter)
app.use(edificioRouter)
app.use(pisoRouter)
app.use(salaRouter)
app.use(ubicacionRouter)
app.use(usuarioRouter)
app.use(wsRouter)
app.use(syncronizeRouter)

app.use('/mobile', mobileRouter)
app.use('/invitations', invitationRouter)
app.use('/access', accessRouter)
// probar
app.use(cmdRouter)
app.use(createCmdRouter)
app.use(realEventRouter)
app.use(timeRouter)
app.use(authorityRouter)
app.use(deviceRouter)
// whatsappClient.initialize()

app.listen(process.env.PORT)


console.log(`Server on port ${process.env.PORT} - ${process.env.AMB}`)
// const endpoints = listEndpoints(app);
// let endp = "";
// let med = "";
// let midd = "";
// endpoints.forEach(({ path, methods, middlewares }) => {
//   med = "";
//   methods.forEach(item => {
//     med += `'${item}',`;
//   })
//   midd = "";
//   methods.forEach(item => {
//     midd += `'${item}',`;
//   })
//   endp += "------------------------------\n";
//   endp += `\tpath: ${path}\n`;
//   endp += `\tmethods: ${med}\n`;
//   endp += `\tmiddlewares: ${midd}\n`;
// })
// fs.appendFile('endpoints.txt', endp, (err) => {
//   if (err) console.error('Error al guardar la solicitud en el archivo:', err)
// })