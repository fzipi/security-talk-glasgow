---?image=assets/img/glasgow.png&position=left&size=55% 100%
@title[Talking Security]

# Talking... Security @fa[lock]

Note: 

- Welcome all
- This is a small talk about security
- Tries to be general (About security), but specific (about our case)

---

## Agenda

- Verification & Validaton
- Context & Codification
- Web problems
- Top Ten
- CSP 
- Defensive Controls
- ASVS

---
## Verification

- Normally it refers to the act of contrasting what was implemented with the requirements.
- In Security, is the act of controlling that input(s) are correct semantically

+++
@title[It this being verified?]

```perl
sub _get_segment_data {
  my ( $self, $db ) = @_;

  $db = $self->{ app_id } unless $db;
  my $dbprefix = $self->{ app_id } eq $db ? "" : "$db.";

  my ( $sql_query, $disp_query );
  if ( my $seg = $self->param( "segment" ) ) {
    $sql_query  = sprintf( "( %s )", $seg );
    if ( $self->param( "segment_description" ) ) {
      $disp_query = $self->param( "segment_description" );
    }
    else {
      $disp_query = $seg;
      $disp_query =~ s/([\d_]+\s*=\s*[\'\"\d]+)/$self->_get_human_segment_desc($1)/eg;
    }
  }
  else {
    local $self->{ never_use_ro_dbh } = 1;
    my $cached = $self->_cache(
      sprintf( "%s:segments:%s", $db, $self->{ sid } ),
      sub {
        my @segment = $self->_get_first_row(
          $self->_sql_select(
            qq{
SELECT sql_query, disp_query
  FROM ${dbprefix}segments
 WHERE username = ? AND sid = ?},
            $self->{ username }, $self->{ sid }
          )
        );
        return \@segment;
      },
      3600
    );
    ( $sql_query, $disp_query ) = @$cached;
  }

  if ( $sql_query ) {
    $sql_query =~ s/^\s+//g;
    $sql_query =~ s/\s+$//g;
  }

  $self->{ addl_where_text } = $sql_query;
  $self->{ disp_query      } = $disp_query;
  $self->{ disp_query_text } = $disp_query;

  # Make the "search" menu persist
  $self->_create_search_menu() if $self->_is_html_req();

  return ( $sql_query, $disp_query );
}
```

@[1-2](Well know funcdion)
@[8-9](That takes parameters from outside)
@[40-44](And lucky for us.... wipes all spaces at the beggining and end)

+++
### Do we have a TCB?

- Who do we trust?(tm)
- The OS? The data in the database?

+++
### Typing

@ul

- In the end there is a typing problem
- All the web is a `string`
- But we have different types in our code, and in our DB
- And what about codifications?

@ulend

+++
### Sanitize all inputs

@ul

- All inputs must be sanitized
- The resposibility relies on the `sub` that receives the data (this is easier when using MVC)

@ulend

---
### Validation

- Is the act of dinamically execute and test a program, so it conforms with the actual requirements.
- Do you remember, we already did verification!
- Once we have valid type for our data, is it valid in our context?
- If it is some ID, it is valid and the user can access it?

---
## Context and Codification

@ul

- Codification depends on context.
- You cannot codify output as HTML, if you are outputting JS
- Sanitization will depend on context also (see for example Taint mode)

@ulend

---
## OWASP Top Ten

- A1. Injection
- A2. Broken Authentication and Session Management
...
- A7. XSS (CSP)
...
- A9. Using Components With Known Vulnerabilities
- A10. Insufficient Logging and Monitoring

---
## CSP: Content Security Policy

@fa[fa-arrow-circle-right] It is a declarative policy that informs the user agent what are valid sources to load from. 

`Content-Security-Policy: default-src 'self'`

To tighten further, one can do the following:

`Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';`

### You can't mix HTML & JS or CSS

---
## OWASP Top Ten Defensive Controls

@ul

- C1: Define Security Requirements
- C2: Leverage Security Frameworks and Libraries
- C3: Secure Database Access
- C4: Encode and Escape Data
- C5: Validate All Inputs
- C6: Implement Digital Identity
- C7: Enforce Access Controls
- C8: Protect Data Everywhere
- C9: Implement Security Logging and Monitoring
- C10: Handle All Errors and Exceptions

@ulend

---
## OWASP ASVS
### Application Security Verification Standard

- V1. Architecture, design and threat modelling
- V2. Authentication
- V3. Session management
- V4. Access control
- V5. Malicious input handling
- V7. Cryptography at rest
- V8. Error handling and logging
- V9. Data protection
...


