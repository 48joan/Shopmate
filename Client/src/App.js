
import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
// import Product from './Components/Product';
import ProductDetail from './Components/ProductDetail';
import HomePage from './Pages/Homepage';
import AdminProductManagement from './Components/ProductManagement'; // Import the admin page
import AdminDashboard from './Components/AdminDashboard';
import ProductManagement from './Components/ProductManagement';
import CategoryManagement from './Components/CategoryManagement';
import OrderManagement from './Components/OrderManagement';
import UserManagement from './Components/UserManagement';
import RegisterForm from './Components/Auth/RegisterForm';
import LoginForm from './Components/Auth/LoginForm';
import Cart from './Components/Cart';
import CartPage from './Pages/CartPage';
// import OrderPage from './Pages/OrderPage';
import Checkout from './Components/Checkout';
// import Header from './Components/Header'
import Profile from './Components/Profile';
import Support from "./Components/Support";
import Private from './Components/PrivateRoute';

function App() {
  return (
    
      <Router>
          <Routes>
            
            <Route path="/register" element={<RegisterForm />} />
            <Route path="/checkout" element={<Checkout />} />
            <Route path="/Cart" element={<Cart />} />
            <Route path="/CartPage" element={<CartPage />} />
            <Route path="/login" element={<LoginForm />} />
            <Route path="/products/:id" element={<ProductDetail />} />
            <Route path="/" element={<HomePage />}>
            <Route path="/admin" element={<AdminDashboard element={<AdminProductManagement />} />} />{/* Admin page */}
            <Route path="/admin/products/add" element={<ProductManagement />} />
            <Route path="/admin/products" element={<ProductManagement />} />
            <Route path="/admin/products/edit/:id" element={<ProductManagement />} />
            <Route path="/admin/categories" element={<CategoryManagement />} />
            <Route path="/admin/categories/edit/:id" element={<CategoryManagement />} />
            <Route path="/admin/users" element={<UserManagement />} />
            <Route path="/admin/users/edit/:id" element={<UserManagement />} />
            <Route path="/admin/orders" element={<OrderManagement />} />
            <Route path="/admin/orders/edit/:id" element={<OrderManagement />} />
            <Route path='/support' element={<Support/>} />
            <Route path='/profile' element={<Profile/>}/>
            <Route path='*' element={<Private/>}/>
              
            </Route>

          </Routes>             
        
      </Router>
    
  );
};


export default App;
