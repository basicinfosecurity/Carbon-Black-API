class ItemExistsError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 100

class InvalidApiTokenError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 200

class InvalidMD5Error(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 300

class InvalidCommentError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 400

class WhitelistError(ValueError):
	def __init__(self, expression, message):
		self.expression = expression
		self.message = message
		self.exit_code = 500
