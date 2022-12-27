const {
    saveUser,
    loginUser,
    getUser,
    verifyToken,
    buildResponse,
    generateToken
} = require('../app')

let token;
const user = {
    name: "mytest2",
    email: "mytest2@gmail.com",
    password: "Test$2022"
}

test('Create User', async () => {
    let userCreated = await saveUser(user)
    expect(userCreated.toString())
        .toBe(({
            "body": {
                "Operation": "SAVE",
                "Message": "SUCCESS",
                "Item": {
                    "name": user.name,
                    "email": user.email
                }
            },
            "headers": {
                "Content-Type": "application/json"
            },
            "statusCode": 200
        }).toString())

});

test('Get User', async () => {
    let userFounded = await getUser(user.email)
    expect(userFounded.toString())
        .toBe(({
            "Item": {
                "email": user.email,
                "name": user.name
            }
        }).toString())
});

test('Generate Token', async () => {
    const tokenGenerated =
        generateToken({
            "name": user.name,
            "email": user.email
        })
    token = await tokenGenerated
    expect(tokenGenerated).toMatch(/ey/)
});

test('Building Response', async () => {
    expect(buildResponse(200, { testResult: "ok" })
        .toString()).toBe((
            {
                "body": { "testResult": "ok" },
                "headers": { "Content-Type": "application/json" },
                "statusCode": 200
            })
            .toString())
});

test('Verify Token', async () => {
    let verifiedTokenMessage = {
        body: {
            verified: true,
            message: "verified"
        },
        headers: {
            "Content-Type": "application/json"
        },
        statusCode: 200
    }
    let tokenVerified = await verifyToken({ token: token, email: user.email })
    expect(tokenVerified.toString()).toBe(verifiedTokenMessage.toString())
});

test('Login User', async () => {
    let userAndToken = await loginUser({
        email: user.email,
        password: user.password
    })
    expect(userAndToken.toString()).toBe(({}).toString())
});