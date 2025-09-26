// Test file for CodeRabbit integration - Contains intentional issues
import React, { useState, useEffect } from 'react';

// Component with multiple issues for CodeRabbit to detect
const TestComponent: React.FC = () => {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);

  // Issue: API key hardcoded
  const API_KEY = "sk-1234567890abcdef";

  // Issue: useEffect without dependencies
  useEffect(() => {
    fetchData();
  });

  // Issue: No error handling
  const fetchData = async () => {
    setLoading(true);
    const response = await fetch(`/api/data?key=${API_KEY}`);
    const result = response.json(); // Issue: Missing await
    setData(result);
    console.log('Data fetched:', result); // Issue: console.log left in
    setLoading(false);
  };

  // Issue: Duplicate code (should be extracted)
  const handleUserClick = (user: any) => { // Issue: using 'any' type
    if (user.age > 18) {
      user.status = 'adult';
      user.canVote = true;
    }
    // TODO: Implement user update // Issue: TODO comment
    return user;
  };

  const handleCustomerClick = (customer: any) => {
    if (customer.age > 18) {
      customer.status = 'adult';
      customer.canVote = true;
    }
    return customer;
  };

  // Issue: Memory leak - event listener not cleaned up
  useEffect(() => {
    window.addEventListener('resize', handleResize);
  }, []);

  const handleResize = () => {
    // FIXME: This causes performance issues
    document.body.style.width = window.innerWidth + 'px';
  };

  // Issue: Potential SQL injection vulnerability
  const searchUsers = async (query: string) => {
    const response = await fetch(`/api/users?search=${query}`);
    return response.json();
  };

  // Issue: No accessibility attributes
  return (
    <div onClick={() => console.log('clicked')}>
      {loading && <div>Loading...</div>}
      {data.map((item, index) => (
        // Issue: Using index as key
        <div key={index}>
          {/* Issue: No alt text for image */}
          <img src={item.image} />
          <button onClick={() => handleUserClick(item)}>
            Click me
          </button>
        </div>
      ))}
    </div>
  );
};

// Issue: Unused variable
const unusedConfig = {
  secret: "super-secret-password",
  endpoint: "https://api.example.com"
};

export default TestComponent;