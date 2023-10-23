#!/bin/bash

cat << EOF > run.sh
#!/bin/bash
`grep "=" .env | tr '\n' ' '`./mvnw install
EOF

bash run.sh
