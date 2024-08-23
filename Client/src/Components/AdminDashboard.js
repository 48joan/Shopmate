import React from 'react';
import { Link } from 'react-router-dom';

const AdminDashboard = () => {
    return (
        <div className="container mx-auto px-4 py-8">
            <h1 className="text-3xl font-bold mb-8 text-black">Admin Dashboard</h1>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white p-6 rounded shadow-md border border-black">
                    <h2 className="text-xl font-bold mb-4">Products</h2>
                    <Link to="/admin/products" className="text-blue-500 hover:underline">Manage Products</Link>
                </div>
                <div className="bg-white p-6 rounded shadow-md border border-black">
                    <h2 className="text-xl font-bold mb-4">Categories</h2>
                    <Link to="/admin/categories" className="text-blue-500 hover:underline">Manage Categories</Link>
                </div>
                <div className="bg-white p-6 rounded shadow-md border border-black">
                    <h2 className="text-xl font-bold mb-4">Users</h2>
                    <Link to="/admin/users" className="text-blue-500 hover:underline">Manage Users</Link>
                </div>
                <div className="bg-white p-6 rounded shadow-md border border-black">
                    <h2 className="text-xl font-bold mb-4">Orders</h2>
                    <Link to="/admin/orders" className="text-blue-500 hover:underline">Manage Orders</Link>
                </div>
            </div>
        </div>
    );
};

export default AdminDashboard;
