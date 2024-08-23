import React from 'react';
import Header from '../Components/Header'
import Home from '../Components/Home'
import ProductList from '../Components/Product';

const HomePage = () => {
  return (
    <div className="homepage-container">
        {/* Section Below Header (Categories, Slideshow, Links) */}
        <Header />

        <Home />

        {/* Product List */}
        <div className="product-list-section py-8">
            <h2 className="text-center text-3xl font-bold mb-6">Our Products</h2>
            <ProductList />
        </div>
    </div>
);
};

export default HomePage;
