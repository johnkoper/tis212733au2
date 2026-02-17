rule tcb212733rule1
{
  strings:
    $test_string= "smoke test"
  condition:
    $test_string
}

rule tcb212733rule2
{
	strings:
        $ = "12345" nocase wide ascii
        $ = "67890" nocase wide ascii                
        $ = {00 01 02 03 04 05}
	condition:
		any of ($*)
}

rule tcb212733rule3 {
  strings:
    $test_string= "asdf jkla"
  condition:
    $test_string
}

