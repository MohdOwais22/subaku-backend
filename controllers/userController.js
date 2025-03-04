const ErrorHander = require("../utils/errorhander");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");
const cloudinary = require("cloudinary");

const axios = require("axios");
const { log } = require("console");

// Helper function for Cloudinary upload with retry logic
const uploadWithRetry = async (image, options, maxRetries = 3) => {
  let attempts = 0;

  while (attempts < maxRetries) {
    try {
      return await cloudinary.v2.uploader.upload(image, options);
    } catch (error) {
      attempts++;
      console.log(`Upload attempt ${attempts} failed. Error: ${error}`);

      if (attempts === maxRetries) {
        throw error;
      }

      // Exponential backoff (2s, 4s, 8s, etc.)
      const backoffTime = 2000 * Math.pow(2, attempts);
      console.log(`Retrying in ${backoffTime / 1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, backoffTime));
    }
  }
};

// Register a User
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
  console.log("Before");

  try {
    // Use the retry function for more reliable uploads
    const myCloud = await uploadWithRetry(req.body.avatar, {
      folder: "avatars",
      width: 150,
      crop: "scale",
      quality: "auto", // Automatically adjusts quality
      fetch_format: "auto", // Ensures optimal format
      timeout: 300000, // Increased timeout to 5 minutes
      chunk_size: 6000000, // Enable chunked uploads for large files (6MB chunks)
      resource_type: "auto" // Handle different file types automatically
    });

    console.log(myCloud);

    const { name, email, password } = req.body;
    console.log("UserName", name);

    const user = await User.create({
      name,
      email,
      password,
      avatar: {
        public_id: myCloud.public_id,
        url: myCloud.secure_url,
      },
    });

    console.log("After User Creation");

    sendToken(user, 201, res);
  } catch (error) {
    console.error("Error:", error);

    // Provide more specific error messages for common upload issues
    if (error.http_code === 429) {
      return res.status(429).json({
        success: false,
        error: "Too many upload requests. Please try again later."
      });
    }

    if (error.http_code === 413) {
      return res.status(413).json({
        success: false,
        error: "Image is too large. Please upload a smaller image (max 10MB)."
      });
    }

    return res.status(500).json({ success: false, error: error.message });
  }
});


// Login User
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  const { email, password } = req.body;

  // Check if email and password are provided
  if (!email || !password) {
    return next(new ErrorHander("Please Enter Email & Password", 400));
  }

  // Find user in database
  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    return next(new ErrorHander("Invalid email or password", 401));
  }

  // Check if password matches
  const isPasswordMatched = await user.comparePassword(password);

  if (!isPasswordMatched) {
    return next(new ErrorHander("Invalid email or password", 401));
  }

  // Set token in cookie
  const token = user.getJWTToken();

  // Cookie options
  const options = {
    expires: new Date(
      Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Secure only in production
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
  };

  // Set the cookie properly
  res.cookie("token", token, options);
  console.log('Setting cookie with options:', options);
  console.log('Cookie headers:', res.getHeaders());
  // Send response with user data and token
  res.status(200).json({
    success: true,
    user,
    token,
  });
});

// exports.loginUser = catchAsyncErrors(async (req, res, next) => {
//   const { email, password } = req.body;

//   // checking if user has given password and email both

//   if (!email || !password) {
//     return next(new ErrorHander("Please Enter Email & Password", 400));
//   }

//   const user = await User.findOne({ email }).select("+password");

//   if (!user) {
//     return next(new ErrorHander("Invalid email or password", 401));
//   }

//   const isPasswordMatched = await user.comparePassword(password);

//   if (!isPasswordMatched) {
//     return next(new ErrorHander("Invalid email or password", 401));
//   }

//   sendToken(user, 200, res);
// });

// Logout User
exports.logout = catchAsyncErrors(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });

  res.status(200).json({
    success: true,
    message: "Logged Out",
  });
});

// Forgot Password
exports.forgotPassword = catchAsyncErrors(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new ErrorHander("User not found", 404));
  }

  // Get ResetPassword Token
  const resetToken = user.getResetPasswordToken();

  await user.save({ validateBeforeSave: false });

  const resetPasswordUrl = `${req.protocol}://${req.get(
    "host"
  )}/password/reset/${resetToken}`;

  const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\nIf you have not requested this email then, please ignore it.`;

  try {
    await sendEmail({
      email: user.email,
      subject: `Ecommerce Password Recovery`,
      message,
    });

    res.status(200).json({
      success: true,
      message: `Email sent to ${user.email} successfully`,
    });
  } catch (error) {
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save({ validateBeforeSave: false });

    return next(new ErrorHander(error.message, 500));
  }
});

// Reset Password
exports.resetPassword = catchAsyncErrors(async (req, res, next) => {
  // creating token hash
  const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: Date.now() },
  });

  if (!user) {
    return next(
      new ErrorHander(
        "Reset Password Token is invalid or has been expired",
        400
      )
    );
  }

  if (req.body.password !== req.body.confirmPassword) {
    return next(new ErrorHander("Password does not password", 400));
  }

  user.password = req.body.password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpire = undefined;

  await user.save();

  sendToken(user, 200, res);
});

// Get User Detail
exports.getUserDetails = catchAsyncErrors(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  res.status(200).json({
    success: true,
    user,
  });
});

// update User password
exports.updatePassword = catchAsyncErrors(async (req, res, next) => {
  const user = await User.findById(req.user.id).select("+password");

  const isPasswordMatched = await user.comparePassword(req.body.oldPassword);

  if (!isPasswordMatched) {
    return next(new ErrorHander("Old password is incorrect", 400));
  }

  if (req.body.newPassword !== req.body.confirmPassword) {
    return next(new ErrorHander("password does not match", 400));
  }

  user.password = req.body.newPassword;

  await user.save();

  sendToken(user, 200, res);
});

// update User Profile
exports.updateProfile = catchAsyncErrors(async (req, res, next) => {
  const newUserData = {
    name: req.body.name,
    email: req.body.email,
  };

  if (req.body.avatar !== "") {
    const user = await User.findById(req.user.id);

    const imageId = user.avatar.public_id;

    await cloudinary.v2.uploader.destroy(imageId);

    // Use the retry function for profile update as well
    const myCloud = await uploadWithRetry(req.body.avatar, {
      folder: "avatars",
      width: 150,
      crop: "scale",
      quality: "auto",
      fetch_format: "auto",
      timeout: 300000,
      chunk_size: 6000000,
      resource_type: "auto"
    });

    newUserData.avatar = {
      public_id: myCloud.public_id,
      url: myCloud.secure_url,
    };
  }

  const user = await User.findByIdAndUpdate(req.user.id, newUserData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });

  res.status(200).json({
    success: true,
  });
});

// Get all users(admin)
exports.getAllUser = catchAsyncErrors(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({
    success: true,
    users,
  });
});

// Get single user (admin)
exports.getSingleUser = catchAsyncErrors(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(
      new ErrorHander(`User does not exist with Id: ${req.params.id}`)
    );
  }

  res.status(200).json({
    success: true,
    user,
  });
});

// update User Role -- Admin
exports.updateUserRole = catchAsyncErrors(async (req, res, next) => {
  const newUserData = {
    name: req.body.name,
    email: req.body.email,
    role: req.body.role,
  };

  await User.findByIdAndUpdate(req.params.id, newUserData, {
    new: true,
    runValidators: true,
    useFindAndModify: false,
  });

  res.status(200).json({
    success: true,
  });
});

// Delete User --Admin
exports.deleteUser = catchAsyncErrors(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(
      new ErrorHander(`User does not exist with Id: ${req.params.id}`, 400)
    );
  }

  const imageId = user.avatar.public_id;

  // Add error handling for image deletion
  try {
    await cloudinary.v2.uploader.destroy(imageId);
  } catch (error) {
    console.error("Error deleting image from Cloudinary:", error);
    // Continue with user deletion even if image deletion fails
  }

  await user.remove();

  res.status(200).json({
    success: true,
    message: "User Deleted Successfully",
  });
});

exports.generateDesign = catchAsyncErrors(async (req, res) => {
  const { prompts } = req.body;

  try {
    const response = await axios.post(process.env.API_URL, {
      "model": "dall-e-3",
      "prompt": prompts,
      "n": 1,
      "size": "1024x1024"
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.API_KEY}`,
      },
      timeout: 60000 // Add request timeout for external API
    });
    const designUrl = response.data.data[0].url;
    res.status(200).json({
      designUrl
    });
  } catch (error) {
    console.error('Error generating design:', error);
    res.status(500).json({
      success: false,
      error: error.response?.data?.error?.message || 'Error generating design'
    });
  }
});

exports.proxyImage = catchAsyncErrors(async (req, res) => {
  try {
    const { imageUrl } = req.body;

    if (!imageUrl) {
      return res.status(400).json({
        success: false,
        error: 'Image URL is required'
      });
    }

    const response = await axios.get(imageUrl, {
      responseType: 'arraybuffer',
      timeout: 30000 // Add timeout for external image fetch
    });

    // Set appropriate content type header
    const contentType = response.headers['content-type'];
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }

    res.send(Buffer.from(response.data, 'binary'));
  } catch (error) {
    console.error('Error proxying image:', error);
    res.status(500).json({
      success: false,
      error: 'Error proxying image'
    });
  }
});