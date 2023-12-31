# Transform Fitness Gym Website

Welcome to the Transform Fitness Gym website project. This README provides an overview of the project, how to set it up, and how to use it effectively.

## Table of Contents

- [Project Description](#project-description)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Folder Structure](#folder-structure)
- [Contributing](#contributing)
- [License](#license)

## Project Description

The Transform Fitness Gym Website is a web application designed for fitness enthusiasts, gym members, and potential clients. It provides information about the gym, services offered, membership options, and allows users to shop for products, services, and memberships.

## Features

List the key features of the Transform Fitness Gym Website, for example:

- **User Authentication**: Secure login and registration for gym members.
- **Product Management**: Admin can add, edit, and delete gym products.
- **Service Management**: Admin can manage fitness services.
- **Membership Management**: Admin can handle membership plans.
- **Shopping Cart**: Users can add gym products, services, and memberships to their cart.
- **Payment Processing**: Integration with Razorpay for secure payments.
- **Admin Dashboard**: Separate dashboard for administrators with revenue tracking.
- **Google OAuth Login**: Simplified login with Google OAuth.

## Installation

Here are the steps to set up and run the Transform Fitness Gym Website:

### Prerequisites

Before you begin, ensure you have the following installed:

- Python
- Flask
- SQLAlchemy
- Razorpay API credentials
- Google OAuth API credentials

### Installation Steps

1. Clone the repository:

   ```shell
   git clone https://github.com/yourusername/transform-fitness-gym-website.git

2.Navigate to the project directory:
   cd transform-fitness-gym-website

3.Create a virtual environment:
   python -m venv venv

4.Activate the virtual environment:
  On Windows:
    venv\Scripts\activate'
  On macOS and Linux:
    source venv/bin/activate

5.Install dependencies:
  pip install -r requirements.txt

6.Configure Razorpay and Google OAuth API credentials in your environment.

7.Create a SQLite database:
  flask db init
  flask db migrate 
  flask db upgrade

8.Run the application:
  flask run

9. Access the website in your browser at http://localhost:5000.
