NEW_PASS=$(openssl rand -base64 64 | tr -d '\n==/+')

if grep -q "^ADMIN_PASS=" .env; then
    sed -i "s|^ADMIN_PASS=.*|ADMIN_PASS=\"$NEW_PASS\"|" .env
else
    echo -e "\nADMIN_PASS=\"$NEW_PASS\"" >> .env
fi