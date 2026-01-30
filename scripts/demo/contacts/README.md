# KLI Contact Management Demo

This demo exercises the KLI contact management commands.

## Commands Demonstrated

| Command | Description |
|---------|-------------|
| `kli contacts list` | List all contacts |
| `kli contacts add` | Add a new contact or update existing |
| `kli contacts get` | Fetch a single contact by AID or alias |
| `kli contacts rename` | Rename a contact's alias |
| `kli contacts delete` | Remove a contact |

## Running the Demo

```bash
./demo_contacts.sh
```

The script will:
1. Create a temporary keystore
2. Create an identifier
3. Add several contacts with various fields
4. Demonstrate get, rename, and delete operations
5. Clean up the keystore on exit

## Command Usage Examples

### Add a contact
```bash
kli contacts add --name <keystore> \
    --aid <contact-aid> \
    --alias alice \
    --field company=GLEIF \
    --field role=Developer
```

### Get a contact by alias
```bash
kli contacts get --name <keystore> --alias alice
```

### Get a contact by AID
```bash
kli contacts get --name <keystore> --aid <contact-aid>
```

### Rename a contact
```bash
kli contacts rename --name <keystore> --old-alias alice --alias alicia
```

### Delete a contact
```bash
# With confirmation prompt
kli contacts delete --name <keystore> --alias alice

# Skip confirmation
kli contacts delete --name <keystore> --alias alice --yes
```

### Re-resolve a contact OOBI
```bash
kli contacts resolve --name <keystore> --contact-alias alice
```

Note: The `resolve` command requires that the contact has an OOBI URL stored,
which is typically set when initially resolving an OOBI with `kli oobi resolve`.
