const mysql = require("mysql");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { nanoid } = require("nanoid");
const { log } = require("console");
const moment = require('moment');
const Razorpay = require('razorpay');
const session = require('express-session');



const db = mysql.createConnection({
    host: process.env.host,
    user: process.env.user,
    password: process.env.pss,
    database: process.env.DATABASE
});

exports.login = async (req, res) => {
    try {
        const { email, passward } = req.body;
        if (!email || !passward) {
            return res.status(400).render('login', { message: "Please enter email and passward" });
        }


        db.query('select * from user where email=?',
            [email],
            async (error, results) => {
                console.log(results);
                if (results.length <= 0) {
                    return res.status(401).render('login', { message: "Email or Passward  incorrect" });
                } else {
                    if (!(await bcrypt.compare(passward, results[0].passward))) {
                        return res.status(401).render('login', { message: "Email or Passward  incorrect" });
                    }
                    else {
                        const token = jwt.sign({ user: results[0] }, process.env.JWT_SECRET, { expiresIn: '30m' });

                        console.log("The Token is " + token);
                        const cookieOptions = {
                            expires: new Date(
                                Date.now() +
                                process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                            ),
                            httpOnly: true,
                        };
                        res.cookie("demo", token, cookieOptions);
                        res.status(200).redirect("/home");
                    }
                }
            });

    } catch (error) {
        console.log(error);
    }
};


exports.isLoggedIn = async (req, res, next) => {
    const token = req.cookies.demo;
    if (!token) {
        return res.redirect("/login");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (error) {
        console.error("Token verification error:", error);
        res.redirect("/login");
    }
};


exports.refferal = (req, res) => {
    try {
        const userEmail = req.user.email;
        db.query('SELECT reff_id, reff_cash FROM user WHERE email=?', [userEmail], (error, results) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Internal Server Error');
            }

            let reff_id;
            let reff_cash;
            if (results.length > 0) {
                reff_id = results[0].reff_id;
                reff_cash = results[0].reff_cash;
            } else {
                console.log("User not found");
                return res.status(404).send('User not found');
            }

            console.log("referralid is ", reff_id);

            const referralLink = `${process.env.BASE_URL}/register?ref=${reff_id}`;
            console.log("referralLink is ", referralLink);

            res.render('reff_profile', { referralLink, reff_cash });
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error overall');
    }
};


exports.register = (req, res) => {
    console.log(req.body);
    const { name, email, passward, passward2, ref } = req.body;

    const referralCode = ref;

    db.query('SELECT email, reff_id FROM user WHERE email=?', [email], async (error, results) => {
        if (error) {
            console.log(error);
        }

        if (results.length > 0) {
            return res.render('register', {
                message: 'Email already in use, please use a different email.'
            });
        } else if (passward !== passward2) {
            return res.render('register', {
                message: 'Password does not match, please try again.'
            });
        }

        let hashedPassword = await bcrypt.hash(passward, 8);
        console.log(hashedPassword);

        reff_id_main = nanoid(6);
        console.log("Generated reff id:" + reff_id_main)
        db.query('INSERT INTO user SET ?', { name: name, email: email, passward: hashedPassword, reff_id: reff_id_main }, (insertError, insertResults) => {
            if (insertError) {
                console.log(insertError);
                console.log("problem in inserion");
            } else {
                console.log(insertResults);
                console.log("Insertion done successfully ");

                if (referralCode) {
                    db.query('SELECT email,reff_cash,plan FROM user WHERE reff_id=?', [referralCode], (referrerError, referrerResults) => {
                        if (referrerError) {
                            console.log(referrerError);
                            console.log("Refferal code not found in database");
                        } else if (referrerResults.length > 0) {

                            const referrerEmail = referrerResults[0].email;
                            let reff_cash = referrerResults[0].reff_cash;
                            const plan = referrerResults[0].plan;
                            console.log("Refferal email id found");
                            console.log("Refferal cash with amount:" + reff_cash);
                            let new_amount;
                            if (plan === "Basic Plan") {
                                new_amount = reff_cash + 5;
                            } else if (plan === "Standard Plan") {
                                new_amount = reff_cash + 7;
                            } else if (plan === "Premium Plan") {
                                new_amount = reff_cash + 10;
                            } else {
                                new_amount = reff_cash + 1;
                            }
                            console.log(`Referrer Email: ${referrerEmail}`);
                            console.log("New Amount:" + new_amount);
                            db.query('UPDATE user SET reff_cash=? WHERE email=?', [new_amount, referrerEmail], (updateError, updateResults) => {
                                if (updateError) {
                                    console.log(updateError);
                                }
                                else {
                                    console.log("Amount Updated old user");
                                }
                            });
                            db.query('UPDATE user SET reff_cash = reff_cash + 1 WHERE email=?', [email], (updateError, updateResults) => {
                                if (updateError) {
                                    console.log(updateError);
                                }
                                else {
                                    console.log("Amount Updated new user");
                                }
                            });
                        }
                    });
                }

                return res.render('login', {
                    message: 'User registered'
                });
            }
        });
    });
};

exports.withdraw = (req, res) => {
    try {
        const userEmail = req.user.email;
        let actual_amount = req.user.reff_cash;
        const { amount, accountNumber, ifscCode, } = req.body;
        db.query('SELECT email FROM withdraw WHERE email=?', [userEmail], async (error, results) => {
            if (error) {
                console.log(error);
            }


            if (amount > actual_amount) {
                res.render('withdraw', {
                    message: 'Insufficient Balance...'
                });
            }
            else if (amount < 5) {
                res.render('withdraw', {
                    message: 'You need Atleast 5 Doller to withdraw...'
                });
            }
            else {
                const convertToMySQLDateTimeFormat = (dateString) => {
                    const date = new Date(dateString);
                    return date.toISOString().slice(0, 19).replace('T', ' ');
                };

                const dateObject = new Date();
                let date = convertToMySQLDateTimeFormat(dateObject);

                db.query('INSERT INTO withdraw set?', { date: date, email: userEmail, acc_no: accountNumber, ifsc: ifscCode, amount: amount, amount_avl: actual_amount }, (error, results) => {
                    if (error) {
                        console.log(error);
                    } else {
                        console.log(results);
                        return res.render('withdraw', {
                            message: 'withdraw Request Raised'
                        });
                    }
                });
            }

            console.log("start");

            console.log("user email:" + userEmail);
            db.query('SELECT * FROM withdraw WHERE email=?', [userEmail], async (error, results) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Internal Server Error');
                }
                console.log("Query feached");
                res.render('withdraw', { data: results });
                console.log("Data send to front end");
            });
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error overall');
    }

};



exports.adminlogin = async (req, res) => {
    try {
        const { email, passward } = req.body;
        if (!email || !passward) {
            return res.status(400).render('adminlogin', { message: "Please enter email and passward" });
        }


        if (email === "admin@reff.com" && passward === "admin123") {
            const token = jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '30m' });

            console.log("The admin Token is " + token);
            const cookieOptions = {
                expires: new Date(
                    Date.now() +
                    process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
                ),
                httpOnly: true,
            };
            res.cookie("admin", token, cookieOptions);
            res.status(200).redirect("/adminpanel");

        } else {
            return res.status(401).render('adminlogin', { message: "Email or Passward  incorrect" });
        }

    } catch (error) {
        console.log(error);
    }
};


exports.isAdminLoggedIn = async (req, res, next) => {
    const token = req.cookies.admin;
    if (!token) {
        return res.redirect("/adminlogin");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.email = decoded.email;
        next();
    } catch (error) {
        console.error("Token verification error:", error);
        res.redirect("/adminlogin");
    }
};

exports.adminpanel = (req, res) => {
    try {
        const { status, start_date, end_date } = req.body;

        const convertToMySQLDateFormat = (dateString) => {
            return moment(dateString).format('YYYY-MM-DD HH:mm:ss');
        };

        const startDateFormatted = convertToMySQLDateFormat(start_date);
        const endDateFormatted = convertToMySQLDateFormat(end_date);

        if (!start_date && !end_date) {
            if (status === "all") {
                db.query('SELECT * FROM withdraw ', async (error, results) => {
                    if (error) {
                        console.log(error);
                        return res.status(500).send('Error retrieving withdraw requests');
                    }
                    res.render('adminpanel', { data: results });
                });
            } else {
                db.query('SELECT * FROM withdraw WHERE status=? ', [status], async (error, results) => {
                    if (error) {
                        console.log(error);
                        return res.status(500).send('Error retrieving filtered withdraw requests');
                    }
                    res.render('adminpanel', { data: results });
                });
            }
        }

        else if (status === "all") {
            db.query('SELECT * FROM withdraw WHERE `date` BETWEEN ? AND ?', [startDateFormatted, endDateFormatted], async (error, results) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error retrieving withdraw requests');
                }
                res.render('adminpanel', { data: results });
            });
        } else {
            db.query('SELECT * FROM withdraw WHERE status=? AND `date` BETWEEN ? AND ?', [status, startDateFormatted, endDateFormatted], async (error, results) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error retrieving filtered withdraw requests');
                }
                res.render('adminpanel', { data: results });
            });
        }
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error overall');
    }
};


exports.updateStatus = (req, res) => {
    try {
        const { email, withdrawId, status, amount } = req.body;
        db.query('SELECT * FROM withdraw', async (error, results) => {
            if (error) {
                console.log(error);
            }
            db.query('UPDATE withdraw SET status=? WHERE id=?', [status, withdrawId], (error, results) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Internal Server Error');
                }
                console.log("Status change to " + status);
            });


            if (status === "approved") {
                db.query('SELECT * from user where email=?', [email], async (error, results) => {
                    if (error) {
                        console.log(error);
                    } else {
                        let curr_amount = results[0].reff_cash;
                        curr_amount = curr_amount - amount;
                        db.query('UPDATE user SET reff_cash=? WHERE email=?', [curr_amount, email], (error, results) => {
                            if (error) {
                                console.log(error);
                                res.status(500).send('Internal Server Error');
                            } else {

                                console.log("Status change to approveed and amount update in user database");
                            }
                        });
                    }
                });
            }

        });
        db.query('SELECT * FROM withdraw', async (error, results) => {
            if (error) {
                console.log(error);
            }
            res.render('adminpanel', { data: results });

        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error overall');
    }

};

exports.logout = (req, res) => {
    res.clearCookie('demo');
    console.log("cookie clear");
    return res.render('login', {
        message: 'You have successfully logged out!'
    });

};

exports.adminlogout = (req, res) => {
    res.clearCookie('admin');
    console.log("cookie clear");
    return res.render('adminlogin', {
        message: 'Admin Portal logout....'
    });

};

exports.updatedata = (req, res) => {
    try {
        const { email, withdrawId, status, amount } = req.body;
        db.query('SELECT * FROM withdraw WHERE email = ? AND id = ?', [email, withdrawId], (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).send('Internal Server Error');
            } else {
                res.render('updatedata', { data: results });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.handledata = (req, res) => {
    try {
        const { email, amount, withdrawId, acc_no, ifsc } = req.body;
        db.query('UPDATE withdraw SET amount=?, acc_no=?, ifsc=? WHERE id=? ', [amount, acc_no, ifsc, withdrawId], (error, results) => {
            if (error) {
                console.error('Error updating user data:', error);
                return res.status(500).send('Internal Server Error');
            } else {
                console.log("User data updated in the database");
                db.query('SELECT * FROM withdraw', async (error, results) => {
                    if (error) {
                        console.log(error);
                    }
                    res.render('adminpanel', { data: results });

                });
            }
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};



exports.profile = (req, res) => {
    const userEmail = req.user.email;
    db.query('SELECT * FROM user WHERE email = ?', [userEmail], (error, results) => {
        if (error) {
            console.log(error);
            res.status(500).send('Internal Server Error');
        } else {
            res.render('profile', { userData: results });
        }
    });
};

exports.updateprofile = (req, res) => {
    try {
        const { username, email } = req.body;
        const userEmail = req.user.email;
        console.log("new name:" + username);
        console.log("new email:" + email);
        console.log("old email:" + userEmail);
        db.query('UPDATE user SET name=?, email=? WHERE email=? ', [username, email, userEmail], (error, updateResults) => {
            if (error) {
                console.error('Error updating user data:', error);
                return res.status(500).send('Internal Server Error');
            } else {
                console.log("User data updated in the user database");
                db.query('SELECT * FROM user WHERE email = ?', [email], (error, results) => {
                    if (error) {
                        console.log(error);
                        return res.status(500).send('Internal Server Error');
                    } else {
                        console.log("Page render with updated user data");
                        res.render('profile', { userData: results, message: "User profile Update Successful...." });
                    }
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.changepass = (req, res) => {
    try {
        const { oldpass, newpass, conpass } = req.body;
        const userEmail = req.user.email;
        console.log("new pass:" + newpass);
        console.log("confrimed new email:" + conpass);
        console.log("old email:" + oldpass);
        db.query('select * from user where email=?', [userEmail], async (error, results) => {
            if (!(await bcrypt.compare(oldpass, results[0].passward))) {
                return res.status(401).render('changepass', { message: "Old passward is wrong" });
            }
            else if (newpass !== conpass) {
                return res.render('changepass', {
                    message: 'Please enter confrimed passward again'
                });
            }
            else {
                let hashedPassword = await bcrypt.hash(newpass, 8);
                db.query('UPDATE user SET passward=? WHERE email=? ', [hashedPassword, userEmail], (error, updateResults) => {
                    if (error) {
                        console.error('Error updating user data:', error);
                        return res.status(500).send('Internal Server Error');
                    } else {
                        console.log("User Passward in the user database");
                        db.query('SELECT * FROM user WHERE email = ?', [userEmail], (error, results) => {
                            if (error) {
                                console.log(error);
                                return res.status(500).send('Internal Server Error');
                            } else {
                                console.log("Page render with updated user data");
                                res.render('profile', { userData: results, message: "Password Update Successful...." });
                            }
                        });
                    }
                });
                console.log("everything looks fine");
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};


exports.forgetpass = (req, res) => {
    try {
        const { email, oldpass, newpass, conpass } = req.body;
        console.log("emai:" + email);
        console.log("new pass:" + newpass);
        console.log("confrimed new email:" + conpass);
        console.log("old email:" + oldpass);
        db.query('select * from user where email=?', [email], async (error, results) => {
            if (results.length > 0) {
                if (!(await bcrypt.compare(oldpass, results[0].passward))) {
                    return res.status(401).render('forgetpass', { message: "Old passward is wrong" });
                }
                else if (newpass !== conpass) {
                    return res.render('forgetpass', {
                        message: 'Please enter confrimed passward again'
                    });
                }
                else {
                    let hashedPassword = await bcrypt.hash(newpass, 8);
                    db.query('UPDATE user SET passward=? WHERE email=? ', [hashedPassword, email], (error, updateResults) => {
                        if (error) {
                            console.error('Error updating user data:', error);
                            return res.status(500).send('Internal Server Error');
                        } else {
                            console.log("Page render with updated user data");
                            res.render('login', { message: "Password Update Successful...." });
                        }
                    });
                    console.log("everything looks fine");
                }
            }
            else {
                return res.render('forgetpass', {
                    message: 'Wrong Email...'
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};


exports.createOrder = (req, res) => {
    try {
        const { RAZORPAY_ID_KEY, RAZORPAY_SECRET_KEY } = process.env;

        const razorpayInstance = new Razorpay({
            key_id: RAZORPAY_ID_KEY,
            key_secret: RAZORPAY_SECRET_KEY
        });
        const { plan } = req.body;
        let amount;
        if (plan === "Basic Plan") {
            amount = 1 * 100;
        } else if (plan === "Standard Plan") {
            amount = 2 * 100;
        } else {
            amount = 3 * 100;
        }

        const options = {
            amount: amount,
            currency: 'INR',
            receipt: 'manasreghe@gmail.com'
        }
        razorpayInstance.orders.create(options, (err, order) => {
            if (err) {
                console.error("Error creating Razorpay order:", err);
                return res.status(500).send({ success: false, msg: 'Error creating Razorpay order.' });
            } else {
                console.log("Inside Success");
                res.status(200).send({
                    success: true,
                    msg: 'Order Created',
                    order_id: order.id,
                    amount: amount,
                    key_id: RAZORPAY_ID_KEY,
                    product_name: plan,
                    description: plan,
                    contact: "1234567890",
                    name: "Bhushan Kadam",
                    email: "bhushankadam512@gmail.com"
                });
            }
        });



    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};


exports.paymentsuccess = (req, res) => {
    try {
        const { planId, planName } = req.body;
        const userEmail = req.user.email;
        console.log("Payment ID: " + planId);
        console.log("Plan Name: " + planName);
        console.log("User Email: " + userEmail);
        db.query('UPDATE user SET plan=?, order_id=? WHERE email=? ', [planName, planId, userEmail], (error, updateResults) => {
            if (error) {
                console.error('Error updating user data:', error);
                return res.status(500).send('Internal Server Error');
            } else {
                console.log("Payment data updated in the user database");

            }
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};




exports.captcha = (req, res) => {
    try {
        var allValue = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
            't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        var cValue = '';
        for (let i = 0; i < 8; i++) {
            cValue += allValue[Math.floor(Math.random() * allValue.length)];
        }
        console.log("Captcha is: " + cValue);
        const userEmail = req.user.email;
        db.query('SELECT * FROM user WHERE email = ?', [userEmail], (error, results) => {
            if (error) {
                console.log(error);
                res.status(500).send('Internal Server Error');
            } else {
                res.render('home', { correct: results[0].correct, wrong: results[0].wrong, skip: results[0].skip, captcha: cValue });
            }
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.verifyCaptcha = (req, res) => {
    try {
        let { captcha, ccode } = req.body;
        console.log("In Verfify Captcha is: " + captcha);
        console.log("input is is: " + ccode);
        const userEmail = req.user.email;

        if (ccode !== captcha) {
            console.log("Captcha verification failed.");
            db.query('UPDATE user SET wrong = wrong + 1 WHERE email=? ', [userEmail], (error, updateResults) => {
                if (error) {
                    console.error('Error updating wrong count:', error);
                    return res.status(500).send('Internal Server Error');
                }
            });

        } else {
            console.log("Captcha verification passed.");
            db.query('UPDATE user SET correct = correct + 1 WHERE email=? ', [userEmail], (error, updateResults) => {
                if (error) {
                    console.error('Error updating right count count:', error);
                    return res.status(500).send('Internal Server Error');
                }
            });
        }
        res.redirect('/home');
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};
exports.skipCaptcha = (req, res) => {
    try {
        const userEmail = req.user.email;
        db.query('UPDATE user SET skip = skip + 1 WHERE email=? ', [userEmail], (error, updateResults) => {
            if (error) {
                console.error('Error updating wrong count:', error);
                return res.status(500).send('Internal Server Error');
            }
        });
        res.redirect('/home');
    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.adminwallet = (req, res) => {
    try {

        const { plan } = req.body;
        console.log("Selected plan:" + plan);

        if (plan === "all") {
            db.query('SELECT * FROM user ', async (error, results) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error retrieving withdraw requests');
                }
                res.render('adminplan', { data: results });
            });
        }
        else {
            db.query('SELECT * FROM user WHERE plan=? ', [plan], async (error, results) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error retrieving filtered user requests');
                }
                res.render('adminplan', { data: results });
            });
        }

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.walletupdate = (req, res) => {
    try {

        let { plan, correct, email, amount } = req.body;
        let new_amount = 0;
        let rem = correct % 20;
        correct = correct - rem;
        correct = correct / 20;
        console.log("User Plan:" + plan)

        if (plan === "Basic Plan") {
            new_amount = correct * 5;
        }
        else if (plan === "Standard Plan") {
            new_amount = correct * 7;
        }
        else if (plan === "Premium Plan") {
            new_amount = correct * 10;
        }
        console.log("old amount:" + amount)

        console.log("Varible amount:" + new_amount)
        amount = parseFloat(amount) + parseFloat(new_amount);
        console.log("new amount:" + amount)
        const dateObj = new Date();
        const month = dateObj.getUTCMonth() + 1; 
        const day = dateObj.getUTCDate();
        const year = dateObj.getUTCFullYear();

        const newDate = day + "/" + month + "/"+ year;
        const info = "Your Wallet Update as per you Correct Captchas on "+newDate;
        console.log(info);

        console.log("reamining correct:" + rem)
        db.query('UPDATE user SET reff_cash=?, correct=?,wrong=0,skip=0, info=? WHERE email=?', [amount, rem,info, email], (error, updateResults) => {
            if (error) {
                console.error('Error updating right count count:', error);
                return res.status(500).send('Internal Server Error');
            }
        });
        db.query('SELECT * FROM user ', async (error, results) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error retrieving filtered user requests');
            }
            res.render('adminplan', { data: results });
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error');
    }
};

exports.planaction = (req, res) => {
    try {

        const { email } = req.body;

        db.query('SELECT * FROM user WHERE email=?',[email], async (error, results) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error retrieving withdraw requests');
            }
            res.render('planaction', { data: results });
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error .......');
    }
};
exports.handleplan = (req, res) => {
    try {

        const { email, remark } = req.body;
        const plan = "";

        db.query('UPDATE user SET plan=?, info=? WHERE email=?',[plan,remark,email], async (error, results) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error retrieving withdraw requests');
            }
        });
        db.query('SELECT * FROM user WHERE email=?',[email], async (error, results) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error retrieving withdraw requests');
            }
            res.render('adminplan', { data: results });
        });

    } catch (error) {
        console.log(error);
        res.status(500).send('Internal Server Error .......');
    }
};



