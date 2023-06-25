const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const { Users } = require('../models')
const { sign } = require('jsonwebtoken')
const { validateToken } = require('../middlewares/AuthMiddleware')

//creating account function//
router.post('/create-account', async (req, res) => {
    const { firstName, lastName, email, password } = req.body
    bcrypt.hash(password, 10).then((hash) => {

        Users.create({ firstName: firstName, lastName: lastName, email: email, password: hash })
        res.json({ firstName, lastName, email, password })
    })
})

//login function
router.post('/login', async (req, res) => {
    const { email, password } = req.body
    const user = await Users.findOne({ where: { email: email } })
    if (!user) {
        res.json({ error: 'User does not exist!' })
    }
    bcrypt.compare(password, user.password).then((match) => {
        if (!match) res.json({ error: 'Incorrect password!' })
        const accessToken = sign({ email: user.email, id: user.id }, 'important-secrete')
        res.json(accessToken)
    })
})

//validating token
router.get('/check-token', validateToken, (req, res) => {
    res.json(req.user)
})

//user's info
router.get('/user-info/:id', async (req, res) => {
    const id = req.params.id
    const userInfo = await Users.findByPk(id, { attributes: { exclude: ['password'] } })
    res.json(userInfo)
})

module.exports = router 
