import unittest
from app import validate_password

class TestPasswordValidation(unittest.TestCase):

    def test_valid_password(self):
        result, msg = validate_password("Valid@123")
        self.assertTrue(result)
        self.assertEqual(msg, "Password is valid.")

    def test_short_password(self):
        result, msg = validate_password("S@1a")
        self.assertFalse(result)
        self.assertEqual(msg, "Password must be at least 8 characters long.")

    def test_missing_uppercase(self):
        result, msg = validate_password("secure@123")
        self.assertFalse(result)
        self.assertEqual(msg, "Password must contain at least one uppercase letter.")

    def test_missing_lowercase(self):
        result, msg = validate_password("SECURE@123")
        self.assertFalse(result)
        self.assertEqual(msg, "Password must contain at least one lowercase letter.")

    def test_missing_digit(self):
        result, msg = validate_password("Secure@abc")
        self.assertFalse(result)
        self.assertEqual(msg, "Password must contain at least one digit.")

    def test_missing_special_char(self):
        result, msg = validate_password("Secure123")
        self.assertFalse(result)
        self.assertEqual(msg, "Password must contain at least one special character.")

if __name__ == "__main__":
    unittest.main()
