const express = require("express");
const router = express.Router();
const userController = require('../controllers/users');


router.get("/", (req,res)=>{
    res.render("index");
});

router.get("/register", (req,res)=>{
    res.render("register");
});

router.get("/login", (req,res)=>{
    res.render("login");
});

router.get("/logout",userController.logout, (req,res)=>{
    res.render('login', {
        message: 'You have successfully logged outtt!'
    });
});
router.get("/adminlogout",userController.adminlogout, (req,res)=>{
    res.render('adminlogin', {
        message: 'Admin Portal Logout...'
    });
});

router.get("/home", userController.isLoggedIn,userController.captcha,(req,res)=>{
    if(req.user){
        res.render("home",{user: req.user});
    }else{
        res.redirect("/login");
    }
});

router.get("/profile",userController.isLoggedIn, userController.profile,(req,res)=>{
    if(req.user){
        res.render("profile",{user: req.user});
    }else{
        res.redirect("/login");
    }
});

router.get("/reff_profile", userController.isLoggedIn,userController.refferal,(req,res)=>{
    if(req.user){
        res.render("reff_profile",{user: req.user});
    }else{
        res.redirect("/login");
    }
});

router.get("/withdraw", userController.isLoggedIn,(req,res)=>{
    if(req.user){
        res.render("withdraw",{user: req.user});
    }else{
        res.redirect("/login");
    }
});

router.get("/adminlogin",  (req,res)=>{
    res.render("adminlogin");
});

router.get("/adminpanel", userController.isAdminLoggedIn,(req,res)=>{
    if(req.email){
        res.render("adminpanel",{email: req.email});
    }else{
        res.redirect("/adminlogin");
    }
});

router.get("/adminplan", userController.isAdminLoggedIn,(req,res)=>{
    if(req.email){
        res.render("adminplan",{email: req.email});
    }else{
        res.redirect("/adminlogin");
    }
});

router.get("/updatedata", userController.isAdminLoggedIn,(req,res)=>{
    if(req.email){
        res.render("updatedata",{email: req.email});
    }else{
        res.redirect("/adminlogin");
    }
});

router.get("/planaction", userController.isAdminLoggedIn,(req,res)=>{
    if(req.email){
        res.render("planaction",{email: req.email});
    }else{
        res.redirect("/adminlogin");
    }
});


router.get("/profile",userController.profile, (req,res)=>{
    res.render('profile', {
        data:results
    });
});

router.get("/changepass", userController.isLoggedIn,(req,res)=>{
    if(req.user){
        res.render("changepass");
    }else{
        res.redirect("/login");
    }
});
router.get("/forgetpass", (req,res)=>{
    res.render("forgetpass");
});

router.get("/plans", userController.isLoggedIn,(req,res)=>{
    if(req.user){
        res.render("plans",{user: req.user});
    }else{
        res.redirect("/login");
    }
});

router.get("/tnc", userController.isLoggedIn,(req,res)=>{
    if(req.user){
        res.render("tnc",{user: req.user});
    }else{
        res.redirect("/login");
    }
});


module.exports = router;