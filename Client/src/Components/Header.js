import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useStateValue } from '../ContextAPI/StateProvider';
import { actionTypes } from '../ContextAPI/Reducer';
import AccountCircleOutlinedIcon from '@mui/icons-material/AccountCircleOutlined';
import ShoppingCartIcon from '@mui/icons-material/ShoppingCart';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import SearchIcon from '@mui/icons-material/Search';
import axios from 'axios';

function Header() {
    const [input, setInput] = useState("");
    const navigate = useNavigate();
    const [{ basket, user }, dispatch] = useStateValue();
    const [dropdownVisible, setDropdownVisible] = useState(false);

    const toggleDropdown = () => {
        setDropdownVisible(!dropdownVisible);
    };

    const auth = async () => {
        if (user) {
            try {
                await axios.post('https://shopmate-sbxu.onrender.com/logout'); // Replace with your logout endpoint
                dispatch({
                    type: actionTypes.SET_USER,
                    user: null,
                });
            } catch (error) {
                console.error("Error logging out", error);
            }
        }
    };

    // SEARCH
    function search(e) {
        e.preventDefault();

        dispatch({
            type: actionTypes.SET_SEARCH_TERM,
            term: input,
        });

        navigate(`/search?query=${encodeURIComponent(input)}`);
    }

    return (
        <nav className="header bg-white shadow-md p-4 m-4 flex items-center justify-between">
            <Link to="/">
                <img className="header__logo h-20" src="https://i.pinimg.com/236x/7e/ef/ca/7eefca1379ab43610e4c9e3b370accaf.jpg" alt="Logo" />
            </Link>

            {/* Searchbar */}
            <form onSubmit={search} className="flex items-center space-x-2 border border-gray-300 rounded-md px-2 py-1">
                <SearchIcon className='text-gray-500' />
                <input 
                    value={input} 
                    onChange={(e) => setInput(e.currentTarget.value.toLowerCase())} 
                    type='text' 
                    placeholder="Search products, brands and categories" 
                    className='w-full border-none outline-none px-2 py-1'
                />
                <button
                    type="submit"
                    className="bg-blue-500 text-white px-4 py-1 rounded-md hover:bg-blue-600"
                >
                    SEARCH
                </button>
            </form>

            {/* Nav links */}
            <div className="flex items-center space-x-4">
                <div className="relative" onMouseLeave={toggleDropdown}>
                    <div className="flex items-center space-x-1 cursor-pointer" onMouseEnter={toggleDropdown}>
                        <AccountCircleOutlinedIcon />
                        <span className="text-gray-700">Account</span>
                    </div>
                    {dropdownVisible && (
                        <div className="absolute right-0 mt-2 w-48 bg-white border border-gray-200 shadow-lg rounded-md">
                            {user ? (
                                <>
                                    <Link to="/profile">
                                        <div className="px-4 py-2 text-sm hover:bg-gray-100">My Account</div>
                                    </Link>
                                    <Link to="/orders">
                                        <div className="px-4 py-2 text-sm hover:bg-gray-100">Orders</div>
                                    </Link>
                                    <Link to="/saveditems">
                                        <div className="px-4 py-2 text-sm hover:bg-gray-100">Saved Items</div>
                                    </Link>
                                    {user.isAdmin && (
                                        <Link to="/admin">
                                            <div className="px-4 py-2 text-sm hover:bg-gray-100">Admin</div>
                                        </Link>
                                    )}
                                    <div
                                        className="px-4 py-2 text-sm hover:bg-gray-100 cursor-pointer"
                                        onClick={auth}
                                    >
                                        Logout
                                    </div>
                                </>
                            ) : (
                                <>
                                    <Link to="/login">
                                        <div className="px-4 py-2 text-sm hover:bg-gray-100">Sign In</div>
                                    </Link>
                                    <Link to="/register">
                                        <div className="px-4 py-2 text-sm hover:bg-gray-100">Register</div>
                                    </Link>
                                </>
                            )}
                        </div>
                    )}
                </div>
                
                <Link to="/help" className='flex items-center space-x-1 text-gray-700'>
                    <HelpOutlineIcon />
                    <span>Help</span>
                </Link>
                <Link to="/checkout" className='flex items-center space-x-1 text-gray-700'>
                    <ShoppingCartIcon />
                    <span>{basket?.length}</span>
                </Link>
            </div>
        </nav>
    );
}

export default Header;
