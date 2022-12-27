const AWS = require('aws-sdk')
AWS.config.update({
  region: process.env.REGION,
  endpoint: `http://dynamodb.${process.env.REGION}.amazonaws.com`,
  accessKeyId: process.env.ACCESS_KEY,
  secretAccessKey: process.env.SECRET_KEY
})
const dynamodb = new AWS.DynamoDB.DocumentClient()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const validator = require('validator')
const passwordValidator = require('password-validator')
const schemaPassword = new passwordValidator()
const schemaName = new passwordValidator()
const userTable = 'user-login'
const healthPath = '/health'
const registerPath = '/register'
const loginPath = '/login'
const verifyPath = '/verify'

exports.handler = async (event) => {
  let response;
  switch (true) {
    case event.httpMethod === 'GET' && event.path === healthPath:
      response = {
        statusCode: 200,
        body: "welcome lambda login!"
      }
      break;
    case event.httpMethod === 'POST' && event.path === registerPath:
      response = await saveUser(JSON.parse(event.body));
      break;
    case event.httpMethod === 'POST' && event.path === loginPath:
      response = await loginUser(JSON.parse(event.body));
      break;
    case event.httpMethod === 'POST' && event.path === verifyPath:
      response = await verifyToken(JSON.parse(event.body));
      break;
    default:
      response = {
        statusCode: 404,
        body: "not found"
      }
      break;
  }
  return response
}

async function saveUser(requestBody) {
  if (!requestBody.name || !requestBody.email || !requestBody.password) return buildResponse(400, {
    message: "Verifique os dados e tente novamente."
  })
  schemaName
    .is().min(3)
    .is().max(20)
  if (!schemaName.validate(requestBody.name)) {
    return buildResponse(400, {
      message: "Nome deve ter no mínimo 3 e no máximo 20 caracteres"
    })
  }
  if (!validator.isEmail(requestBody.email)) {
    return buildResponse(400, {
      message: "Por favor insira um email válido."
    })
  }
  schemaPassword
    .is().min(8)
    .is().max(20)
    .has().uppercase()
    .has().lowercase()
    .has().digits(2)
    .has().not().spaces()
  if (!schemaPassword.validate(requestBody.password)) {
    return buildResponse(400, {
      message: "Formato de senha invalido."
    })
  }
  const encryptPassWord = bcrypt.hashSync(requestBody.password.trim(), 10)
  requestBody.password = encryptPassWord
  requestBody.name = requestBody.name.toLowerCase().trim()
  const params = {
    TableName: userTable,
    Item: requestBody
  }
  return await dynamodb.put(params).promise().then(() => {
    delete requestBody.password
    const body = {
      Operation: 'SAVE',
      Message: 'SUCCESS',
      Item: requestBody
    }
    return buildResponse(200, body);
  }, (error) => {
    console.error('Erro ao incluir usuário', error);
  })
}

async function loginUser(user) {
  const email = user.email
  const password = user.password
  if (!user || !email || !password) {
    return buildResponse(401, {
      message: "email and password are required"
    })
  }
  const dynamoUser = await getUser(email)
  if (!dynamoUser.Item) {
    return buildResponse(403, {
      message: "User or password is incorrect"
    })
  }
  if (!bcrypt.compareSync(password, dynamoUser.Item.password)) {
    return buildResponse(403, {
      message: 'User or password is incorrect'
    })
  }
  const userInfo = {
    name: dynamoUser.Item.name,
    email: dynamoUser.Item.email
  }
  const token = generateToken(userInfo)
  const response = {
    user: userInfo,
    token: token
  }
  return buildResponse(200, response)
}

async function getUser(email) {
  const params = {
    TableName: userTable,
    Key: {
      email: email
    }
  }
  return await dynamodb.get(params).promise().then(response => {
    return response;
  }, error => {
    console.error("Error", error)
  })
}

function generateToken(user) {
  if (!user) return null
  return jwt.sign(user, process.env.JWT_SECRET || "OneStrongKey", {
    expiresIn: '1h'
  })
}

async function verifyToken(payload) {
  return jwt.verify(
    payload.token,
    process.env.JWT_SECRET || "OneStrongKey",
    (error, response) => {
      if (error) {
        return buildResponse(400, {
          verified: false,
          message: 'Invalid token'
        })
      }
      if (response.email != payload.email) {
        return buildResponse(400, {
          verified: false,
          message: 'Invalid token'
        })
      }
      return buildResponse(200, {
        verified: true,
        message: 'verified'
      })

    }
  )
}

function buildResponse(statusCode, body) {
  return {
    statusCode: statusCode,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  }
}

//Usado somente para testes
// module.exports = {
//   saveUser,
//   loginUser,
//   getUser,
//   verifyToken,
//   buildResponse,
//   generateToken
// }