const express = require("express");
const router = express.Router();
const userController = require('../controllers/users');

router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/adminlogin', userController.adminlogin);
router.post('/refferal', userController.isLoggedIn, userController.refferal);
router.post('/withdraw', userController.isLoggedIn, userController.withdraw);
// router.post('/profile', userController.isLoggedIn, userController.profile);
router.post('/updateprofile',userController.isLoggedIn, userController.updateprofile);
router.post('/changepass',userController.isLoggedIn, userController.changepass);
router.post('/createOrder',userController.isLoggedIn, userController.createOrder);
router.post('/paymentsuccess',userController.isLoggedIn, userController.paymentsuccess);
router.post('/forgetpass', userController.forgetpass);
router.post('/captcha',userController.isLoggedIn, userController.captcha);
router.post('/verifyCaptcha',userController.isLoggedIn, userController.verifyCaptcha);
router.post('/skipCaptcha',userController.isLoggedIn, userController.skipCaptcha);



router.post('/adminpanel',userController.isAdminLoggedIn, userController.adminpanel);
router.post('/updateStatus',userController.isAdminLoggedIn, userController.updateStatus);
router.post('/updatedata',userController.isAdminLoggedIn, userController.updatedata);
router.post('/handledata',userController.isAdminLoggedIn, userController.handledata);
router.post('/adminwallet',userController.isAdminLoggedIn, userController.adminwallet);
router.post('/walletupdate',userController.isAdminLoggedIn, userController.walletupdate);
router.post('/planaction',userController.isAdminLoggedIn, userController.planaction);
router.post('/handleplan',userController.isAdminLoggedIn, userController.handleplan);








module.exports = router;

