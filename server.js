// =================================================================
// JC NEXUS HUB - Main Server File (Updated & Complete)
// =================================================================
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const path = require('path');

// =================================================================
// Initial Setup
// =================================================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// =================================================================
/* Database */
// =================================================================
mongoose.connect(MONGO_URI)
  .then(()=>console.log('MongoDB connected successfully.'))
  .catch(err=>console.error('MongoDB connection error:', err));

// =================================================================
/* Schemas & Models */
// =================================================================
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email:     { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['Employee','Admin','IT','Cleaning','Canteen','Store'], default: 'Employee' },
  employeeId: { type: String, required: true, unique: true },
  department: String,
  pic: String,
  phone: String,
  address: String,
  joiningDate: { type: Date, default: Date.now },
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const chatMessageSchema = new mongoose.Schema({
  senderId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  senderName: String,
  senderRole: String,
  message:   String,
  timestamp:  { type: Date, default: Date.now },
});

const ticketSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  requesterName: String, 
  department: String,
  floorNumber: String,
  tableNumber: String,
  mainIssue: String,
  problemDescription: String,
  priority: { type: String, default: 'Normal', enum: ['Normal', 'High'] },
  status: { type: String, default: 'Pending', enum: ['Pending', 'In Progress', 'Resolved', 'Cancelled'] },
  chatHistory: [chatMessageSchema],
  resolvedBy: String,
  resolutionNote: String,
  resolvedAt: Date,
  rating: Number,
  review: String,
}, { timestamps: true });
const Ticket = mongoose.model('Ticket', ticketSchema);

const cleaningRequestSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  requesterName: String,
  department: String,
  floorNumber: String,
  deskNumber: String,
  cleaningType: String,
  status: { type: String, default: 'Pending', enum: ['Pending', 'In Progress', 'Completed', 'Cancelled'] },
  chatHistory: [chatMessageSchema],
  completedBy: String,
  closingNote: String,
  completedAt: Date,
  rating: Number,
  review: String,
}, { timestamps: true });
const CleaningRequest = mongoose.model('CleaningRequest', cleaningRequestSchema);

const orderSchema = new mongoose.Schema({
  employeeId: { type: String, required: true },
  requesterName: String,
  department: String,
  beverage: String,
  floorNumber: String,
  deskNumber: String,
  instructions: String,
  status: { type: String, default: 'Pending', enum: ['Pending', 'Delivered', 'Cancelled'] },
  chatHistory: [chatMessageSchema],
  completedAt: Date,
  rating: Number,
  review: String,
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);

const foodOrderSchema = new mongoose.Schema({
    employeeId: { type: String, required: true },
    requesterName: String,
    department: String,
    items: [{
        name: String,
        quantity: Number,
        price: Number
    }],
    totalPrice: Number,
    timePreference: String,
    deliveryTime: String,
    paymentMethod: String,
    customFoodRequest: String,
    instructions: String,
    status: { type: String, default: 'Pending', enum: ['Pending', 'Preparing', 'Ready for Pickup', 'Delivered', 'Cancelled'] },
    chatHistory: [chatMessageSchema],
    completedAt: Date,
    rating: Number,
    review: String,
}, { timestamps: true });
const FoodOrder = mongoose.model('FoodOrder', foodOrderSchema);

const storeRequestSchema = new mongoose.Schema({
    employeeId: { type: String, required: true },
    requesterName: String,
    department: String,
    floorNumber: String,
    tableNumber: String,
    itemName: String,
    quantity: Number,
    comments: String,
    status: { type: String, default: 'Pending', enum: ['Pending', 'Approved', 'Delivered', 'Cancelled'] },
    chatHistory: [chatMessageSchema],
    deliveredBy: String,
    dispatchNote: String,
    completedAt: Date,
    rating: Number,
    review: String,
}, { timestamps: true });
const StoreRequest = mongoose.model('StoreRequest', storeRequestSchema);

const broadcastSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    senderName: String,
    senderRole: String,
    message: String,
}, { timestamps: true });
const Broadcast = mongoose.model('Broadcast', broadcastSchema);

// =================================================================
/* Middleware */
// =================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname, { extensions: ['html'] }));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'a_very_secret_key_for_jc_nexus_hub',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }, // 7 days
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

const isAuthenticated = (req,res,next)=> req.session.userId ? next() : res.redirect('/');
const hasRole = (...roles)=>(req,res,next)=> (req.session.userRole && roles.includes(req.session.userRole)) ? next() : res.status(403).send('<h1>403 Forbidden: Access Denied</h1>');

// =================================================================
/* HTML Routes */
// =================================================================
app.get('/', (req,res)=>{
  if (req.session.userId){
    switch(req.session.userRole){
      case 'Admin':   return res.redirect('/admin-dashboard');
      case 'IT':      return res.redirect('/it-dashboard');
      case 'Cleaning': return res.redirect('/cleaning-dashboard');
      case 'Canteen':  return res.redirect('/canteen-dashboard');
      case 'Store':    return res.redirect('/store-dashboard');
      default:       return res.redirect('/employee-dashboard');
    }
  }
  res.sendFile(path.join(__dirname,'index.html'));
});

// Auth Pages
app.get('/register', (req,res)=> res.sendFile(path.join(__dirname,'register.html')));

// Dashboard Pages
const dashboards = ['employee-dashboard', 'admin-dashboard', 'it-dashboard', 'cleaning-dashboard', 'canteen-dashboard', 'store-dashboard'];
dashboards.forEach(dash => {
    app.get(`/${dash}.html`, isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, `${dash}.html`)));
    app.get(`/${dash}`, (req, res) => res.redirect(`/${dash}.html`));
});

// Feature Pages
const featurePages = ['submit-ticket', 'order-beverage', 'request-cleaning', 'request_preorder', 'request_store'];
featurePages.forEach(page => {
    app.get(`/${page}`, isAuthenticated, (req,res)=> res.sendFile(path.join(__dirname,`${page}.html`)));
});

// Logout
app.get('/logout', (req,res)=>{
  req.session.destroy(()=> res.redirect('/'));
});

// =================================================================
/* Auth APIs */
// =================================================================
app.post('/api/login', async (req,res)=>{
  try{
    const { email,password } = req.body;
    const user = await User.findOne({ email, status: { $ne: 'Inactive' } }); 
    if(!user) return res.status(401).json({message:'Invalid credentials or user inactive.'});
    const ok = await bcrypt.compare(password,user.password); if(!ok) return res.status(401).json({message:'Invalid credentials or user inactive.'});
    
    req.session.userId = user._id; req.session.userRole = user.role; req.session.fullName = user.fullName; req.session.employeeId = user.employeeId;
    
    let redirectUrl = '/employee-dashboard';
    if (user.role==='Admin') redirectUrl='/admin-dashboard';
    else if (user.role==='IT') redirectUrl='/it-dashboard';
    else if (user.role==='Cleaning') redirectUrl='/cleaning-dashboard';
    else if (user.role==='Canteen') redirectUrl='/canteen-dashboard';
    else if (user.role==='Store') redirectUrl='/store-dashboard';
    
    res.json({success:true, redirectUrl});
  }catch(e){ res.status(500).json({message:'Server error during login.'}); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { fullName, email, password, role, employeeId, department } = req.body;
        if (!fullName || !email || !password || !employeeId) {
            return res.status(400).json({ message: 'Missing required fields.' });
        }
        const existingUser = await User.findOne({ $or: [{ email }, { employeeId }] });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email or employee ID already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ fullName, email, password: hashedPassword, role, employeeId, department });
        await newUser.save();
        res.status(201).json({ success: true, message: 'User registered successfully!' });
    } catch (e) {
        console.error("Registration Error:", e);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.get('/api/user-info', isAuthenticated, async (req,res)=> {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.json(user);
    } catch(e) {
        res.status(500).json({ message: 'Server error fetching user info.' });
    }
});

app.put('/api/profile/update', isAuthenticated, async (req, res) => {
    try {
        const { address, phone, pic } = req.body;
        const updatedUser = await User.findByIdAndUpdate(req.session.userId, { address, phone, pic }, { new: true }).select('-password');
        res.json(updatedUser);
    } catch(e) {
        res.status(500).json({ message: 'Server error updating profile.' });
    }
});

// =================================================================
/* Employee APIs (My Requests + Create) */
// =================================================================
app.get('/api/employee/my-requests', isAuthenticated, hasRole('Employee','Admin'), async (req,res)=>{
  try{
    const employeeId = req.session.employeeId;
    const [tickets, orders, cleaning, foodOrders, storeRequests] = await Promise.all([
      Ticket.find({employeeId}).sort({createdAt:-1}),
      Order.find({employeeId}).sort({createdAt:-1}),
      CleaningRequest.find({employeeId}).sort({createdAt:-1}),
      FoodOrder.find({employeeId}).sort({createdAt:-1}),
      StoreRequest.find({employeeId}).sort({createdAt:-1}),
    ]);
    res.json({tickets, orders, cleaning, foodOrders, storeRequests});
  }catch{ res.status(500).json({message:'Server error loading requests.'}); }
});

const createRequestHandler = (Model, eventName) => async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const doc = await Model.create({ 
            ...req.body, 
            employeeId: req.session.employeeId, 
            requesterName: req.session.fullName,
            department: user ? user.department : ''
        });
        io.emit(eventName, doc);
        io.emit('new-request-admin', doc);
        res.status(201).json(doc);
    } catch (e) {
        console.error(`Error creating ${Model.modelName}:`, e);
        res.status(500).json({ message: `Server error creating ${Model.modelName}.` });
    }
};

app.post('/api/tickets', isAuthenticated, createRequestHandler(Ticket, 'new-ticket'));
app.post('/api/cleaning/requests', isAuthenticated, createRequestHandler(CleaningRequest, 'new-cleaning'));
app.post('/api/beverage/orders', isAuthenticated, createRequestHandler(Order, 'new-order'));
app.post('/api/store/requests', isAuthenticated, createRequestHandler(StoreRequest, 'new-store-request'));

app.post('/api/food/pre-order', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const { items, timePreference, deliveryTime, paymentMethod, customFoodRequest, instructions, totalPrice } = req.body;
        const orderData = {
            employeeId: req.session.employeeId,
            requesterName: req.session.fullName,
            department: user ? user.department : '',
            items, timePreference, deliveryTime, paymentMethod, customFoodRequest, instructions,
            totalPrice: parseFloat(String(totalPrice).replace('₹', ''))
        };
        const doc = await FoodOrder.create(orderData);
        io.emit('new-food-order', doc);
        io.emit('new-request-admin', doc);
        res.status(201).json(doc);
    } catch (e) {
        console.error(`Error creating complex FoodOrder:`, e);
        res.status(500).json({ message: `Server error creating FoodOrder.` });
    }
});


const getDetailsHandler = (Model) => async (req, res) => {
    try {
        const doc = await Model.findById(req.params.id);
        if (!doc) return res.status(404).json({ message: `${Model.modelName} not found.`});
        if (req.session.userRole === 'Employee' && doc.employeeId !== req.session.employeeId) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        res.json(doc);
    } catch (e) {
        res.status(500).json({ message: `Server error fetching ${Model.modelName}.` });
    }
};

app.get('/api/ticket/details/:id', isAuthenticated, getDetailsHandler(Ticket));
app.get('/api/cleaning/details/:id', isAuthenticated, getDetailsHandler(CleaningRequest));
app.get('/api/beverage/details/:id', isAuthenticated, getDetailsHandler(Order));
app.get('/api/food/details/:id', isAuthenticated, getDetailsHandler(FoodOrder));
app.get('/api/store/details/:id', isAuthenticated, getDetailsHandler(StoreRequest));

const submitRatingHandler = (Model, idField) => async (req, res) => {
    try {
        const { rating, review } = req.body;
        const id = req.body[idField];
        await Model.updateOne({ _id: id, employeeId: req.session.employeeId }, { rating, review });
        res.sendStatus(200);
    } catch (e) {
        res.status(500).json({ message: `Server error submitting rating for ${Model.modelName}.` });
    }
};

app.post('/api/tickets/submit-rating', isAuthenticated, submitRatingHandler(Ticket, 'ticketId'));
app.post('/api/cleaning/submit-rating', isAuthenticated, submitRatingHandler(CleaningRequest, 'requestId'));
app.post('/api/beverages/submit-rating', isAuthenticated, submitRatingHandler(Order, 'requestId'));
app.post('/api/food/submit-rating', isAuthenticated, submitRatingHandler(FoodOrder, 'requestId'));
app.post('/api/store/submit-rating', isAuthenticated, submitRatingHandler(StoreRequest, 'requestId'));

app.get('/api/broadcasts', isAuthenticated, async (req, res) => {
    try {
        const broadcasts = await Broadcast.find({}).sort({ createdAt: -1 });
        res.json(broadcasts);
    } catch (e) {
        res.status(500).json({ message: 'Error fetching broadcasts.' });
    }
});


// =================================================================
/* Staff APIs (IT, Cleaning, Canteen, Store) */
// =================================================================

// --- IT Staff ---
app.get('/api/it/dashboard-data', isAuthenticated, hasRole('IT','Admin'), async (req, res) => {
    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const [tickets, broadcasts] = await Promise.all([
            Ticket.find({}).sort({ createdAt: -1 }).lean(),
            Broadcast.find({}).sort({ createdAt: -1 }).limit(10).lean()
        ]);
        const stats = {
            highPriority: tickets.filter(t => t.priority === 'High' && (t.status === 'Pending' || t.status === 'In Progress')).length,
            pending: tickets.filter(t => t.status === 'Pending').length,
            inProgress: tickets.filter(t => t.status === 'In Progress').length,
            resolvedToday: tickets.filter(t => t.status === 'Resolved' && new Date(t.resolvedAt) >= todayStart).length
        };
        res.json({ stats, tickets, broadcasts });
    } catch (error) {
        console.error("Error fetching IT dashboard data:", error);
        res.status(500).json({ message: 'Server error loading IT dashboard data.' });
    }
});

app.post('/api/it/update-priority', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
    try {
        const { ticketId, priority } = req.body;
        const ticket = await Ticket.findByIdAndUpdate(ticketId, { priority }, { new: true });
        io.emit('ticket-updated', ticket);
        res.status(200).json({ success: true, message: 'Priority updated.'});
    } catch(e) { 
        res.status(500).json({ message: 'Server Error updating priority.' });
    }
});

app.post('/api/it/update-status', isAuthenticated, hasRole('IT','Admin'), async (req,res)=>{
    try {
        const { ticketId, newStatus, resolutionNote } = req.body;
        let updateQuery = { status: newStatus };
        if (newStatus === 'Resolved' || newStatus === 'Cancelled') {
            updateQuery.resolvedBy = req.session.fullName;
            updateQuery.resolvedAt = new Date();
            updateQuery.resolutionNote = resolutionNote;
        }
        const ticket = await Ticket.findByIdAndUpdate(ticketId, updateQuery, { new: true });
        io.emit('ticket-updated', ticket);
        io.emit('request-updated-admin', ticket);
        res.json(ticket);
    } catch(e) {
        console.error("IT update status error:", e);
        res.status(500).json({ message: 'Server Error updating status.' });
    }
});


// --- Cleaning Staff ---
app.get('/api/cleaning/dashboard-data', isAuthenticated, hasRole('Cleaning','Admin'), async (req, res) => {
    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const [tasks, broadcasts] = await Promise.all([
            CleaningRequest.find({}).sort({ createdAt: -1 }).lean(),
            Broadcast.find({}).sort({ createdAt: -1 }).limit(10).lean()
        ]);
        const stats = {
            pending: tasks.filter(t => t.status === 'Pending').length,
            inProgress: tasks.filter(t => t.status === 'In Progress').length,
            completedToday: tasks.filter(t => t.status === 'Completed' && t.completedAt && new Date(t.completedAt) >= todayStart).length
        };
        res.json({ stats, tasks, broadcasts });
    } catch (error) {
        console.error("Error fetching Cleaning dashboard data:", error);
        res.status(500).json({ message: 'Server error loading Cleaning dashboard data.' });
    }
});

app.post('/api/cleaning/update-status', isAuthenticated, hasRole('Cleaning','Admin'), async (req,res)=>{
    try {
        const { requestId, status, closingNote } = req.body;
        const update = { status };
        if (status === 'Completed' || status === 'Cancelled') {
            update.closingNote = closingNote;
            update.completedBy = req.session.fullName;
            update.completedAt = new Date();
        }
        const request = await CleaningRequest.findByIdAndUpdate(requestId, update, { new: true });
        io.emit('cleaning-updated', request);
        io.emit('request-updated-admin', request);
        res.json(request);
    } catch(e) { 
        console.error("Cleaning update status error:", e);
        res.status(500).send('Server Error'); 
    }
});


// --- Canteen Staff ---
app.get('/api/canteen/dashboard-data', isAuthenticated, hasRole('Canteen','Admin'), async (req, res) => {
    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const [foodOrders, beverageOrders, broadcasts] = await Promise.all([
            FoodOrder.find({}).sort({ createdAt: -1 }).lean(),
            Order.find({}).sort({ createdAt: -1 }).lean(),
            Broadcast.find({}).sort({ createdAt: -1 }).limit(10).lean()
        ]);
        const stats = {
            pendingFood: foodOrders.filter(o => o.status === 'Pending').length,
            pendingBeverage: beverageOrders.filter(o => o.status === 'Pending').length,
            deliveredToday: [
                ...foodOrders.filter(o => o.status === 'Delivered' && o.completedAt && new Date(o.completedAt) >= todayStart),
                ...beverageOrders.filter(o => o.status === 'Delivered' && o.completedAt && new Date(o.completedAt) >= todayStart)
            ].length
        };
        res.json({ stats, foodOrders, beverageOrders, broadcasts });
    } catch (error) {
        console.error("Error fetching Canteen dashboard data:", error);
        res.status(500).json({ message: 'Server error loading Canteen dashboard data.' });
    }
});

app.post('/api/canteen/update-status', isAuthenticated, hasRole('Canteen','Admin'), async (req,res)=>{
    try{
        const { orderId, status, orderType } = req.body;
        const Model = orderType === 'food' ? FoodOrder : Order;
        const eventName = orderType === 'food' ? 'food-order-updated' : 'order-updated';
        const update = { status };
        if (status === 'Delivered' || status === 'Cancelled') {
            update.completedAt = new Date();
        }
        const order = await Model.findByIdAndUpdate(orderId, update, { new: true });
        io.emit(eventName, order);
        io.emit('request-updated-admin', order);
        res.json(order);
    }catch(e) { 
        console.error("Canteen update status error:", e);
        res.status(500).send('Server Error'); 
    }
});


// --- Store Staff ---
app.get('/api/store/dashboard-data', isAuthenticated, hasRole('Store','Admin'), async (req, res) => {
    try {
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        const [requests, broadcasts] = await Promise.all([
            StoreRequest.find({}).sort({ createdAt: -1 }).lean(),
            Broadcast.find({}).sort({ createdAt: -1 }).limit(10).lean()
        ]);
        const stats = {
            pending: requests.filter(r => r.status === 'Pending').length,
            approved: requests.filter(r => r.status === 'Approved').length,
            deliveredToday: requests.filter(r => r.status === 'Delivered' && r.completedAt && new Date(r.completedAt) >= todayStart).length,
        };
        res.json({ stats, requests, broadcasts });
    } catch (error) {
        console.error("Error fetching Store dashboard data:", error);
        res.status(500).json({ message: 'Server error loading Store dashboard data.' });
    }
});

app.post('/api/store/update-status', isAuthenticated, hasRole('Store','Admin'), async (req,res)=>{
    try{
        const { requestId, status, dispatchNote } = req.body;
        const update = { status };
        if (status === 'Delivered' || status === 'Cancelled') {
            update.completedAt = new Date();
            update.deliveredBy = req.session.fullName;
            update.dispatchNote = dispatchNote;
        }
        const request = await StoreRequest.findByIdAndUpdate(requestId, update, {new: true});
        io.emit('store-request-updated', request);
        io.emit('request-updated-admin', request);
        res.json(request);
    }catch(e){ 
        console.error("Store update status error:", e);
        res.status(500).send('Server error'); 
    }
});

// =================================================================
/* Admin APIs */
// =================================================================
app.get('/api/admin/dashboard-data', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const [users, tickets, cleaning, orders, foodOrders, storeRequests, broadcasts] = await Promise.all([
            User.find({}).select('-password').lean(),
            Ticket.find({}).sort({ createdAt: -1 }).lean(),
            CleaningRequest.find({}).sort({ createdAt: -1 }).lean(),
            Order.find({}).sort({ createdAt: -1 }).lean(),
            FoodOrder.find({}).sort({ createdAt: -1 }).lean(),
            StoreRequest.find({}).sort({ createdAt: -1 }).lean(),
            Broadcast.find({}).sort({ createdAt: -1 }).limit(15).lean()
        ]);

        const allRequests = [...tickets, ...cleaning, ...orders, ...foodOrders, ...storeRequests];
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);

        const stats = {
            userCount: users.length,
            pendingCount: allRequests.filter(r => !['Resolved', 'Completed', 'Delivered', 'Cancelled'].includes(r.status)).length,
            completedToday: allRequests.filter(r => r.completedAt && new Date(r.completedAt) >= todayStart).length,
            openTickets: tickets.filter(t => t.status !== 'Resolved' && t.status !== 'Cancelled').length,
            pendingCleaning: cleaning.filter(c => c.status !== 'Completed' && c.status !== 'Cancelled').length,
            pendingBeverage: orders.filter(o => o.status !== 'Delivered' && o.status !== 'Cancelled').length,
            pendingFood: foodOrders.filter(f => !['Delivered', 'Cancelled'].includes(f.status)).length,
            pendingStore: storeRequests.filter(s => s.status !== 'Delivered' && s.status !== 'Cancelled').length,
        };
        
        const recentActivities = allRequests.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 10);

        res.json({ 
            stats, 
            users, 
            tickets, 
            cleaning, 
            orders, 
            foodOrders, 
            storeRequests, 
            recentActivities, 
            broadcasts 
        });
    } catch (e) {
        console.error("Admin data fetch error:", e);
        res.status(500).json({ message: 'Server error loading admin dashboard data.' });
    }
});

app.get('/api/admin/user-food-bills', isAuthenticated, hasRole('Admin', 'Canteen'), async (req, res) => {
    try {
        const bills = await FoodOrder.aggregate([
            { $unwind: "$items" },
            { $group: {
                _id: "$employeeId",
                requesterName: { $first: "$requesterName" },
                totalBill: { $sum: { $multiply: ["$items.price", "$items.quantity"] } },
                orderIds: { $addToSet: "$_id" } 
            }},
            { $lookup: { from: "users", localField: "_id", foreignField: "employeeId", as: "userDetails" } },
            { $unwind: { path: "$userDetails", preserveNullAndEmptyArrays: true } },
            { $project: {
                _id: 0,
                employeeId: "$_id",
                fullName: "$requesterName",
                department: "$userDetails.department",
                pic: "$userDetails.pic",
                totalBill: 1,
                totalOrders: { $size: "$orderIds" }
            }},
            { $sort: { totalBill: -1 } }
        ]);
        res.json(bills);
    } catch (e) {
        console.error("Error fetching user food bills:", e);
        res.status(500).json({ message: "Error fetching billing data." });
    }
});


// --- Admin User Management Routes ---
app.post('/api/admin/users', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const { fullName, email, password, role, employeeId, department } = req.body;
        if (!fullName || !email || !password || !employeeId) return res.status(400).json({ message: 'Missing required fields.' });
        const existingUser = await User.findOne({ $or: [{ email }, { employeeId }] });
        if (existingUser) return res.status(409).json({ message: 'User with this email or employee ID already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ fullName, email, password: hashedPassword, role, employeeId, department });
        await newUser.save();
        io.emit('user-list-updated');
        res.status(201).json({ success: true, message: 'User created successfully.' });
    } catch (e) {
        res.status(500).json({ message: 'Server error creating user.' });
    }
});
app.put('/api/admin/users/:id', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const { fullName, email, role, department, employeeId, phone, address, status } = req.body;
        const updateData = { fullName, email, role, department, employeeId, phone, address, status };

        if (req.body.password && req.body.password.trim() !== '') {
            updateData.password = await bcrypt.hash(req.body.password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(req.params.id, updateData, { new: true }).select('-password');
        if (!updatedUser) return res.status(404).json({ message: "User not found."});

        io.emit('user-list-updated');
        res.json(updatedUser);
    } catch (e) {
        res.status(500).json({ message: 'Server error updating user.' });
    }
});
app.delete('/api/admin/users/:id', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'Inactive' }, { new: true });
        if (!user) return res.status(404).json({ message: "User not found."});
        io.emit('user-list-updated');
        res.status(200).json({ message: "User deactivated successfully."});
    } catch (e) {
        res.status(500).json({ message: 'Server error deactivating user.' });
    }
});
app.get('/api/admin/users', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json(users);
    } catch (e) {
        res.status(500).json({ message: 'Error fetching users.' });
    }
});

const models = { ticket: Ticket, cleaning: CleaningRequest, beverage: Order, food: FoodOrder, store: StoreRequest };

app.post('/api/admin/update-request-status', isAuthenticated, hasRole('Admin'), async (req, res) => {
    try {
        const { requestId, requestType, newStatus } = req.body;
        const Model = models[requestType];
        if (!Model) return res.status(400).json({ message: 'Invalid request type.' });
        const update = { status: newStatus };
        if (['Resolved', 'Completed', 'Delivered'].includes(newStatus)) {
            update.completedAt = new Date();
        }
        const updatedDoc = await Model.findByIdAndUpdate(requestId, update, { new: true });
        io.emit('request-updated-admin', updatedDoc);
        res.json(updatedDoc);
    } catch(e) {
        res.status(500).json({ message: 'Error updating status.' });
    }
});

app.post('/api/admin/create-broadcast', isAuthenticated, hasRole('Admin', 'Canteen', 'IT'), async (req, res) => {
    try {
        const { message } = req.body;
        const broadcast = await Broadcast.create({ message, senderId: req.session.userId, senderName: req.session.fullName, senderRole: req.session.userRole });
        io.emit('new-broadcast', broadcast);
        res.status(201).json(broadcast);
    } catch(e) {
        res.status(500).json({ message: 'Error creating broadcast.' });
    }
});

// =================================================================
/* Socket.IO Logic */
// =================================================================
io.on('connection', (socket)=>{
    const sess = socket.request.session;
    if (!sess || !sess.userId) return socket.disconnect();

    socket.on('join-chat-room', ({ type, requestId })=>{
        const roomName = `${type}:${requestId}`;
        socket.join(roomName);
    });

    socket.on('send-chat-message', async ({ type, requestId, message })=>{
        try {
            const Model = models[type];
            if (!Model) return;

            const chatMessage = { senderId: sess.userId, senderName: sess.fullName, senderRole: sess.userRole, message };
            await Model.findByIdAndUpdate(requestId, { $push:{ chatHistory: chatMessage } });
            
            const roomName = `${type}:${requestId}`;
            io.to(roomName).emit('chat-message', { requestId, ...chatMessage });
        } catch(e) { console.error(`Chat error for type ${type}:`, e); }
    });
});

// =================================================================
/* Start */
// =================================================================
server.listen(PORT, ()=> console.log(`JC Nexus Hub server running on http://localhost:${PORT}`));

// =============== END OF JC NEXUS HUB SERVER FILE ===============