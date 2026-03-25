import User from '../models/userModel.js'
import validator from 'validator'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

const JWT_SECRET=process.env.JWT_SECRET || 'your_jwt_secret_key';
const TOKEN_EXPIRES='24h';

const createToken=(userId)=>jwt.sign({id:userId},JWT_SECRET,{expiresIn:TOKEN_EXPIRES});

//REGISTER FUNCTION
export async function registerUser(req, res) {
    const { name, email, password } = req.body;

    if(!name || !email || !password){
        return  res.status(400).json({success:false,message: 'Please fill all the fields' });

    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email' });

    }
    if(password.length<8){
        return res.status(400).json({success:false,message: 'Password must be at least 8 characters long' });
    }
    try{
        if (await User.findOne({ email})){
            return res.status(400).json({ success: false, message: 'User with this email already exists' });
        }
        const hashed=await bcrypt.hash(password,10);
        const user= await User.create({name,email,password:hashed});
        const token=createToken(user._id);

        res.status(201).json({success:true,token,user:{_id:user._id,name:user.name,email:user.email} });

    }
    catch(err){
        console.log(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
}

//LOGIN FUNCTION
export async function loginUser(req, res) {
    const { email, password } = req.body;
    if(!email || !password){
        return res.status(400).json({success:false,message: 'Email and password required' });
    }
    try{
        const user= await User.findOne({email});
        if(!user){
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
        const match= await bcrypt.compare(password,user.password);
        if(!match){
            return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        }
        const token=createToken(user._id);
        res.status(200).json({success:true,token,user:{id:user._id,name:user.name,email:user.email} });

    }
    catch(err){
        console.log(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
}

//GET CURRENT USER 
export async function getCurrentUser(req, res) {
    try{
        const user= await User.findById(req.user.id).select('name email');
        if(!user){
            return res.status(400).json({ success: false, message: 'User not found' });
        }
        res.json({success:true,user})
    }catch(err){
        console.log(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
}

//UPDATE USER PROFILE
export async function updateProfile(req, res) {
    const { name, email } = req.body;
    if(!name || !email || !validator.isEmail(email)){
        return res.status(400).json({success:false,message: 'Please provide valid name and email' });
    }
    try{
        const exists= await User.findOne({email,_id:{$ne:req.user.id}});
        if(exists){
            return res.status(409).json({ success: false, message: 'Email already in use by another account.' });
        }
        const user= await User.findByIdAndUpdate(req.user.id,{name,email},{new:true},{new:true,runValidators:true,select:"name email"});
        res.json({success:true,user})
    }
    catch(err){
        console.log(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
}

//CHANGE PASSWORD FUNCTION
export async function updatePassword(req, res) {
    const { oldPassword, newPassword } = req.body;
    if(!oldPassword || !newPassword || newPassword.length<8){
        return res.status(400).json({success:false,message: "Password invalid or too short" });
    }
    try{
        const user= await User.findById(req.user.id).select("password");
        if(!user){
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const match= await bcrypt.compare(oldPassword,user.password);
        if(!match){
            return res.status(401).json({ success: false, message: 'Old password is incorrect' });
        }
        user.password= await bcrypt.hash(newPassword,10);
        await user.save();
        res.json({success:true,message: 'Password updated successfully' });
    }
    catch(err){
        console.log(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
}