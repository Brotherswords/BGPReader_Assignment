# Event start goes from 17:28:00 to 17:32:00 on 10/22/2024
# Define the attacker ASN, victim ASN, and target prefix
attacker_asn = "203"
victim_asn = "8220"
target_prefix = "213.41.16.0/24"

# Open the input file and the output file
with open("event_start.txt", "r") as file, open(
    "filtered_results.txt", "w"
) as output_file:
    for line in file:
        # Split the line into fields using '|' as a delimiter
        fields = line.strip().split("|")

        # Check if there are enough fields in the line (some may be malformed)
        if len(fields) > 11:
            as_path = fields[11]  # AS path is the 12th field (index 11)
            prefix = fields[8]  # Prefix is the 9th field (index 8)

            # Check if the attacker ASN, victim ASN, or target prefix appears
            if (
                attacker_asn in as_path
                or victim_asn in as_path
                or prefix == target_prefix
            ):
                output_file.write(line)  # Write the matching line to the output file
