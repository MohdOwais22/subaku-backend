// Create Token and saving in cookie

const sendToken = (user, statusCode, res) => {
  const token = user.getJWTToken();

  // options for cookie
  const options = {
    expires: new Date(
      Date.now() + 1000 * 24 * 60 * 60 * 1000 * 1000 // process.env.COOKIE_EXPIRE * 
    ),
    secure: false,
    sameSite: "None",
    httpOnly: true,
  };

  res.cookie("token", token, options);
  res.json({
    success: true,
    user,
    token,
  });
  console.log("Token Send");
};

module.exports = sendToken;
