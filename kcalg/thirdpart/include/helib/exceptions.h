//Header guard
#ifndef HELIB_EXCEPTIONS_H
#define HELIB_EXCEPTIONS_H

#include <exception>
#include <stdexcept>
#include <sstream>

/**
 * @file exceptions.h
 * @brief Various HElib-specific exception types.
 *
 * This is largely a mirror image of the standard library exceptions, with the
 * added ancestor of `helib::Exception`.  This allows one to distinguish between
 * general exceptions and those specifically thrown by HElib.  For example:
 *
 * ```
 try {
   // Some code including calls to HElib
 }
 catch(const helib::Exception& err) {
   // HElib error handling
 }
 catch(const std::exception& err) {
   // Generic error handling
 }
 * ```
 *
 * To make sure that this is a pattern that can be used, we should only throw
 * exceptions derived from `helib::Exception` wherever possible.
 */

/* @namespace helib*/
namespace helib {

/**
 * @class Exception
 * @brief Base class that other HElib exception classes inherit from.
 */
class Exception
{
  public:
    virtual ~Exception() = default;
    /** @fn what returns a pointer to the string of the exception message*/
    virtual const char* what() const noexcept = 0;
  protected:
    Exception() = default;
};
  
/**
 * @class LogicError
 * @brief Inherits from helib::Exception and std::logic_error.
 */
class LogicError : public std::logic_error, public ::helib::Exception
{
public:
  explicit LogicError(const std::string& what_arg) : std::logic_error(what_arg) {};
  explicit LogicError(const char* what_arg) : std::logic_error(what_arg) {};
  virtual ~LogicError(){};
  /** @fn what returns a pointer to the string of the exception message*/
  virtual const char* what() const noexcept override {return std::logic_error::what();};
};

/**
 * @class OutOfRangeError
 * @brief Inherits from helib::Exception and std::out_of_range.
 */
class OutOfRangeError : public std::out_of_range, public ::helib::Exception
{
public:
  explicit OutOfRangeError(const std::string& what_arg) : std::out_of_range(what_arg) {};
  explicit OutOfRangeError(const char* what_arg) : std::out_of_range(what_arg) {};
  virtual ~OutOfRangeError(){};
  /** @fn what returns a pointer to the string of the exception message*/
  virtual const char* what() const noexcept override {return std::out_of_range::what();};
};

/**
 * @class RuntimeError
 * @brief Inherits from helib::Exception and std::runtime_error.
 */
class RuntimeError : public std::runtime_error, public ::helib::Exception
{
public:
  explicit RuntimeError(const std::string& what_arg) : std::runtime_error(what_arg) {};
  explicit RuntimeError(const char* what_arg) : std::runtime_error(what_arg) {};
  virtual ~RuntimeError(){};
  /** @fn what returns a pointer to the string of the exception message*/
  virtual const char* what() const noexcept override {return std::runtime_error::what();};
};
  
/**
 * @class InvalidArgument
 * @brief Inherits from helib::Exception and std::invalid_argument.
 */
class InvalidArgument : public std::invalid_argument, public ::helib::Exception
{
public:
  explicit InvalidArgument(const std::string& what_arg) : std::invalid_argument(what_arg) {};
  explicit InvalidArgument(const char* what_arg) : std::invalid_argument(what_arg) {};
  virtual ~InvalidArgument(){};
  /** @fn what returns a pointer to the string of the exception message*/
  virtual const char* what() const noexcept override {return std::invalid_argument::what();};
};
  
  
} // End of namespace
#endif // End of header guard
