import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import generateTokenAndSetCookie from "../utils/generateToken.js";

export const signup = async (req, res) => {
    try {
        const {fullname, username, password, confirmPassword, gender: genderInput} = req.body;
        const gender = genderInput ? genderInput.toLowerCase() : "";
        
        if (password !== confirmPassword) {
            return res.status(400).json({message: "Passwords do not match"});
        }

        const user = await User.findOne({username});
        if (user) {
            return res.status(400).json({message: "User already exists"});
        }

        // Hash password here
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // https://avatar-placeholder.iran.liara.run/public/boy?username=Scott
        const boyProfile = `https://avatar-placeholder.iran.liara.run/public/boy?username=${username}`;
        const girlProfile = `https://avatar-placeholder.iran.liara.run/public/girl?username=${username}`;
        
        const newUser = new User({
            fullname,
            username,
            password: hashedPassword,
            gender,
            profilePicture: gender === "male" ? boyProfile : girlProfile
        });

        if (newUser) {
            // Generate JWT token here
            generateTokenAndSetCookie(newUser._id, res);
            await newUser.save();
            res.status(201).json({
                _id: newUser._id,
                fullname: newUser.fullname,
                username: newUser.username,
                profilePicture: newUser.profilePicture
            })
        }else {
            res.status(400).json({message: "Invalid User data"});
        }
        
    } catch (error) {
        console.log("Error in signup controller", error);
        return res.status(500).json({message: "Something went wrong"});
    }
}

export const login = async (req, res) => {
    try {
        const {username, password} = req.body;

        const user = await User.findOne({username});
        const isPasswordValid = await bcrypt.compare(password, user?.password || "");
        if (!user || !isPasswordValid) {
            return res.status(400).json({message: "Invalid username or password"});
        }
        generateTokenAndSetCookie(user._id, res);
        res.status(200).json({
            _id: user._id,
            fullname: user.fullname,
            username: user.username,
            profilePicture: user.profilePicture
        });

    } catch (error) {
        console.log("Error in login controller", error);
        return res.status(500).json({message: "Something went wrong"});
    }
}

export const logout = (req, res) => {
    try {
        res.cookie("jwt", "", { maxAge: 0 });
        res.status(200).json({message: "User logged out successfully"});
        
    } catch (error) {
        console.log("Error in logout controller", error);
        return res.status(500).json({message: "Something went wrong"});
    }
}