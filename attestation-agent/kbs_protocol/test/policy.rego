package policy

default allow = false

allow if {
	# EAR draft-04 uses separate attester and verifier claim maps.
	input.submods.cpu0.ear_attester_claims.tee == "sample"
}

allow if {
	# Retain compatibility with KBS images issuing the older EAR format.
	input["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["sample"]
}
