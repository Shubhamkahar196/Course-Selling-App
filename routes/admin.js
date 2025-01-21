const { Router } = require("express");
const adminRouter = Router();
const { adminModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const { JWT_ADMIN_PASSWORD } = require("../config");
const bcrypt = require("bcrypt");
const z = require("zod");
const { adminMiddleware } = require("../middleware/admin");



adminRouter.post("/signup", async function (req, res) {

    //input validation using zod

    const requireBody = z.object({
        email: z.string().email().min(5),
        password: z.string().min(4).max(15),
        firstName: z.string().min(3).max(15),
        lastName: z.string().min(3).max(15)
    });


    // Parse the request body using the requireBody.safeParse() method to validate the data format
    // "safe" parsing (doesn't throw error if validation fails)

    const parseDataSuccess = requireBody.safeParse(req.body);

    //if data is not correct then yeh response return krdo

    if (!parseDataSuccess.success) {
        return res.json({
            message: "Incorrect Format",
            error: parseDataSuccess.error


        })
    }

    //extract validated email, password , firstName and lastName from the requres ho  

    const { email, password, firstName, lastName } = req.body;

    //hash the admin password using bcrypt with  a salt rounds of 5
    const hashedPassword = await bcrypt.hash(password, 5);

    //creating a admin in the database
    try {
        await adminModel.create({
            email,
            password: hashedPassword,
            firstName,
            lastName
        });
    } catch (e) {
        // If there is an error during user creation, return a error message
        return res.status(400).json({
            // Provide a message indicating signup failure
            message: "You are already signup"
        })

    }

    // Send a success response back to client indicating successfully singup

    res.json({
        message: "admin signup succesfully"
    })
})

adminRouter.post("/signin", async function (req, res) {

    // Validate the request body data using zod schema(email,password must be valid)
    const requireBody = z.object({
        email: z.string().email(),
        password: z.string().min(5),
    });

    // Parse and validate the request body data
    const parseDataWithSuccess = requireBody.safeParse(req.body);
    // If the data format is incorrect, send an error message to the client
    if (!parseDataWithSuccess) {
        return res.json({
            message: "Incorrect data format",
            error: parseDataWithSuccess.error,
        })
    }

    // Get the email and password from the request body
    const { email, password } = req.body;
    // Find the admin with the given email

    const admin = await adminModel.findOne({
        email: email,
    });

    // If the admin is not found, send an error message to the client

    if (!admin) {
        return res.status(403).json({
            message: "Invalid credentials",
        })
    }

    // Compare the password with the hashed password using the bcrypt.compare() method
    const passswordMatch = await bcrypt.compare(password, admin.password);


    // If password matches, generate a jwt token and return it

    if (passswordMatch) {
        // Create a jwt token with the admin's id and the secret key
        const token = jwt.sign({
            id: admin._id
        }, JWT_ADMIN_PASSWORD);

        //send the generated token back to client
        res.json({
            token: token,
        });
    } else {
        // If the password does not match, send an error message to the client
        res.status(403).json({
            message: "Invalid credentials!"
        });
    }

    res.json({
        message: "admin signin"
    })
})



adminRouter.post("/course", adminMiddleware, async function(req,res) {
    // Get the adminId from the request object
    const adminId = req.userId;

    // Validate the request body data using zod schema
    const requireBody = z.object({
        title: z.string().min(3),
        description: z.string().min(10),
        imageUrl: z.string().url(),
        price: z.number().positive(),
    });
    // Parse and validate the request body data
    const parseDataWithSuccess = requireBody.safeParse(req.body);

    // If the data format is incorrect, send an error message to the client
    if(!parseDataWithSuccess){
        return res.json({
            message: "Incorrect data format",
            error: parseDataWithSuccess.error,
        });
    }

    // Get title, description, imageURL, price from the request body
    const {title,description,imageUrl,price} = req.body;

    // Create a new course with the given title, description, imageURL, price, creatorId
    const course = await courseModel.create({
        title:title,
        description:description,
        imageUrl:imageUrl,
        price:price,
        creatorId:adminId,
    });

    // Respond with a success message if the course is created successfully
    res.status(201).json({
        message: "Course Created",
        courseId: course._id,
    });
});



// adminRouter.put("/course",adminMiddleware, async function (req, res) {
//     // Get the adminId from the request object, set by the admin middleware
    
//     const adminId = req.userId;

//     //define a schema using zod to validate the request body for updating a course

//     const requireBody = z.object({
//         courseId: z.string().min(5),  // ensure course ID is at least 5 characters
//         title: z.string().min(3).optional(),  // title is optional
//         description: z.string().min(5).optional(), // description is optional
//         imageUrl: z.string().url().min(5).optional(), // image url is option
//     })
     
//     //parse and validate the incoming request body against the schema
//     const parseDataWithSuccess = requireBody.safeParse(req.body);

//     // if validation fails respond with an error message and the details of the error

//     if(!parseDataWithSuccess){
//         return res.json({
//             message: "Incorrect data format",
//             error: parseDataWithSuccess.error,
//         });
//     }

//      // extract the validate fields from the body
//      const { title, description,imageUrl,price,courseId} = req.body;

//      //find the course in the database using adminId and courseID

//      const course = await courseModel.findOne({
//         _id: courseId,  // match the course by ID
//         creatorId: adminId // ensure the admin is the creator
//      });

//      // if the course is not found respond with an error message
//      if(!course){
//         return res.status(404).json({
//             message: "Course not found"
//         });
//      }

//      // update the course details in the database using the object

//      await courseModel.updateOne({
//         _id: courseId,
//         creatorId: adminId
//      },{
//         // it uses the provided courseId and adminId to identify the course. for each
//         title: title || course.title,
//         description: description || course.description,
//         imageUrl: imageUrl || course.imageUrl,
//         price: price || course.price,
//      });

//     res.status(200).json({
//         message: "Course updated !"
//     })
// });

adminRouter.put("/course", adminMiddleware, async function(req,res) {
    // Get the adminId from the request object, set by the admin middleware
    const adminId = req.userId;

    // Define a schema using zod to validate the request body for updating a course
    const requireBody = z.object({
        courseId: z.string().min(5), // Ensure course ID is at least 5 characters
        title: z.string().min(3).optional(), // Title is optional
        description: z.string().min(5).optional(), // Description is optional
        imageUrl: z.string().url().min(5).optional(), // Image URL is optional
        price: z.number().positive().optional(), // Price is optional
    });

    // Parse and validate the incoming request body against the schema
    const parseDataWithSuccess = requireBody.safeParse(req.body);

    // If validation fails, respond with an error message and the details of the error
    if(!parseDataWithSuccess){
        return res.json({
            message: "Incorrect data format",
            error: parseDataWithSuccess.error,
        });
    }

    // Destructure the validated fields from the request body
    const {title,description,imageUrl,price,courseId} = req.body;
     // Attempt to find the course in the database using the provided courseId and adminId
     const course = await courseModel.findOne({
        _id: courseId, // Match the course by ID
        creatorId: adminId, // Ensure the admin is the creator
    });

    // If the course is not found, respond with an error message
    if(!course){
        return res.status(404).json({
            message: "Course not found!", // Inform the client that the specified course does not exist
        });
    }

    // Update the course details in the database using the updates object
    await courseModel.updateOne({
        _id: courseId, // Match the course by ID
        creatorId: adminId, // Ensure the admin is the creator
    },
    {
        // It uses the provided courseId and adminId to identify the course. For each field (title, description, imageUrl, price), if a new value is provided, it is used to update the course. If a field is not provided, the existing value from the database is kept.
        title: title || course.title,
        description: description || course.description,
        imageUrl: imageUrl || course.imageUrl,
        price: price || course.price,
    });

    // Respond with a success message upon successful course update
    res.status(200).json({
        message: "Course updated!", // Successfully course updated or not
    });
});

adminRouter.get("/course/bulk",adminMiddleware, async function (req, res) {
    // get the adminId from the request object
    const adminId = req.userId;

    //find all the courses with given creatorId
    const courses = await courseModel.find({
        creatorId: adminId,
    });
    
    res.json({
        message: " get all courses",
        courses: courses
    })
})

module.exports = {
    adminRouter: adminRouter
}