import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Product from './Product';
import Marketing from '../Components/Marketing';


function SectionBelowHeader() {
  const images = [
    {
      src: 'https://i.pinimg.com/236x/e3/6e/36/e36e36d71b92003cb94d88f2301099c6.jpg',
      alt: 'Electronics',
      link: '/category/electronics',
    },
    {
      src: 'https://i.pinimg.com/originals/d8/34/89/d834891a49605bc17f503a7e17e804b8.jpg',
      alt: 'Fashion',
      link: '/category/fashion',
    },
    {
      src: 'https://i.pinimg.com/564x/10/b0/88/10b0884308bc91b4a3685bdd4e20d789.jpg',
      alt: 'Home',
      link: '/category/home',
    },
    // Add more images as needed
  ];

  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [data, setData] = useState([]);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentImageIndex((prevIndex) =>
        prevIndex === images.length - 1 ? 0 : prevIndex + 1
      );
    }, 3000); // Change image every 3 seconds

    return () => clearInterval(interval);
  }, [images.length]);

  useEffect(() => {
    fetch('https://shopmate-sbxu.onrender.com')
      .then((response) => response.json())
      .then((data) => setData(data));
  }, []);

  return (
    <div className="homepage">
      <div className="container mx-auto px-4 max-w-[100%] ">
        <div className="section-below-header flex justify-between items-start h-[30vh]">
          {/* Categories Section */}
          <div className="categories w-1/4 pr-10">
            <h3 className="text-2xl font-bold mb-4">Categories</h3>
            <ul className="list-disc list-inside">
              <li>
                <Link to="/category/electronics" className="hover:underline">
                  Electronics
                </Link>
              </li>
              <li>
                <Link to="/category/fashion" className="hover:underline">
                  Fashion
                </Link>
              </li>
              <li>
                <Link to="/category/home" className="hover:underline">
                  Home
                </Link>
              </li>
              <li>
                <Link to="/category/sports" className="hover:underline">
                  Sports
                </Link>
              </li>
              <li>
                <Link to="/category/beauty" className="hover:underline">
                  Beauty
                </Link>
              </li>
              {/* Add more categories as needed */}
            </ul>
          </div>

          {/* Slideshow Section */}
          <div className="slideshow w-1/2 h-full">
            <a href={images[currentImageIndex].link}>
              <img
                src={images[currentImageIndex].src}
                alt={images[currentImageIndex].alt}
                className="w-full h-full object-contain rounded-md"
              />
            </a>
          </div>

          {/* Right Links Section */}
          <div className="right-links w-1/4 pl-10">
            <ul className="list-none">
              <li className="mb-4">
                <Link to="/help-centre" className="hover:underline">
                  Help Centre
                </Link>
              </li>
              <li className="mb-4">
                <Link to="/easy-return" className="hover:underline">
                  Easy Return
                </Link>
              </li>
              <li>
                <Link to="/sell-on-shopmate" className="hover:underline">
                  Sell on Shopmate
                </Link>
              </li>
            </ul>
          </div>
        </div>

       
          {/* <Footer /> */}
        </div>
    </div>
  );
}

export default SectionBelowHeader;
